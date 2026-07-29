#![recursion_limit = "256"]

use anyhow::{Context, Result, bail};
use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::{Shell, generate};
use pcbex_core::checking::{check_board, check_manufacturability, check_report_to_sarif};
use pcbex_core::placement::{
    CandidateObjective, PlacementCandidateOptions, PlacementCandidateSet, PlacementOptions,
    PlacementProblem, place, place_candidates,
};
use pcbex_core::{
    AnalysisDelta, Board, CURRENT_SCHEMA_VERSION, DfmProfile, RoutingCandidateObjective,
    RoutingCandidateOptions, RoutingCandidateSet, RoutingQuality, Rules, analysis_delta_to_sarif,
    apply_dfm_profile, board_json_schema, dfm_profile, dfm_profile_json_schema, dfm_profiles,
    impedance_report, migrate_board_json, parse_board_json, parse_external_dfm_profile, render_svg,
    repair_routes, repairable_net_ids, route_board, route_candidates, routing_quality,
    solve_stackup_differential_width_nm, solve_stackup_width_nm,
};
use pcbex_kicad::{
    AiApprovalQuorumCandidate, AiApprovalQuorumPolicy, AiApprovalQuorumReport, AiRequirement,
    AiReviewRequest, AiReviewResponse, AiReviewSession, ApprovalArtifactKind,
    ApprovalEventDescriptor, ApprovalLogAnchorProof, ApprovalLogWitnessTrustState,
    ApprovalTransparencyLog, ElectricalPolicy, ElectricalReview, ElectricalWaiverSet,
    HumanEscalationCandidate, HumanEscalationDecision, HumanEscalationPolicy,
    HumanEscalationReport, RoutedAiApprovalQuorumReport, SessionAiApprovalQuorumReport,
    SessionAiQuorumEvidence, SessionRoutedAiApprovalQuorumReport, SignedAiApproval,
    SignedApprovalLogCheckpoint, SignedApprovalLogWitness, SignedApprovalLogWitnessKeyRotation,
    SignedHumanEscalation, SimulationArtifact, SimulationEvidence,
    ai_approval_quorum_report_json_schema, ai_review_request_json_schema,
    ai_review_response_json_schema, append_approval_transparency_event,
    apply_approval_log_witness_key_rotation, apply_custom_design_rules, apply_electrical_waivers,
    apply_project_net_settings, approval_log_anchor_proof_json_schema,
    approval_log_anchor_verification_report_json_schema,
    approval_log_verification_report_json_schema, approval_log_witness_quorum_report_json_schema,
    approval_log_witness_trust_state_json_schema, approval_log_witness_trusted_public_key,
    approval_public_key, approval_transparency_log_json_schema, build_ai_review_request,
    build_ai_review_session, check_schematic, compare_electrical_reviews, compare_schematics,
    create_approval_log_anchor_proof, electrical_explanation_json_schema,
    electrical_policy_json_schema, electrical_review_comparison_json_schema,
    electrical_review_json_schema, electrical_review_to_junit, electrical_review_to_sarif,
    electrical_waiver_report_json_schema, electrical_waiver_set_json_schema,
    explain_electrical_review, human_escalation_report_json_schema, import as import_kicad,
    import_schematic, new_approval_log_witness_trust_state, new_approval_transparency_log,
    parse_ai_review_response, parse_electrical_policy, parse_schematic_reviewer_routing_policy,
    parse_simulation_declaration, record_simulation_evidence, render_ai_approval_quorum_summary,
    render_human_escalation_summary, render_routed_ai_approval_quorum_summary,
    render_schematic_diff_summary, render_schematic_reviewer_routing_summary,
    render_session_routed_ai_approval_quorum_summary, route_schematic_review,
    routed_ai_approval_quorum_report_json_schema, schematic_diff_json_schema,
    schematic_diff_to_sarif, schematic_json_schema, schematic_reviewer_routing_plan_json_schema,
    schematic_reviewer_routing_policy_json_schema, sign_ai_review, sign_ai_review_for_session,
    sign_approval_log_checkpoint, sign_approval_log_witness,
    sign_approval_log_witness_key_rotation, sign_human_escalation, signed_ai_approval_json_schema,
    signed_approval_log_checkpoint_json_schema, signed_approval_log_checkpoint_sha256,
    signed_approval_log_witness_json_schema, signed_approval_log_witness_key_rotation_json_schema,
    signed_human_escalation_json_schema, simulation_declaration_json_schema,
    simulation_evidence_json_schema, verify_ai_approval_quorum, verify_approval_log_anchor_proof,
    verify_approval_log_checkpoint, verify_approval_log_witness_quorum, verify_human_escalation,
    verify_routed_ai_approval_quorum, verify_session_ai_approval_quorum,
    verify_session_routed_ai_approval_quorum, verify_session_signed_ai_approval,
    verify_signed_ai_approval,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    convert::Infallible,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

mod canary_completion;
mod manufacturing_feedback;
mod mcp;
mod policy_deployment;
mod policy_deployment_rollback;
mod policy_deployment_verification;
mod policy_incident_ledger;
mod policy_lifecycle;
mod policy_lifecycle_checkpoint;
mod policy_pack;
mod policy_recommendation;
mod policy_remediation;
mod policy_rollback_recovery;
mod policy_rollout;
mod policy_rollout_approval;
mod policy_suspension;
mod remote_policy;
mod remote_witness;

use canary_completion::{
    CanaryCompletionDecision, canary_completion_json_schema, parse_canary_completion_report,
    parse_signed_canary_decision, render_canary_completion_summary, sign_canary_completion,
    signed_canary_decision_json_schema, verify_canary_completion,
};
use manufacturing_feedback::{
    EvidenceDescriptor, bind_manufacturing_feedback, compare_manufacturing_feedback,
    evidence_descriptor, manufacturing_feedback_comparison_json_schema,
    manufacturing_feedback_comparison_to_sarif, manufacturing_feedback_declaration_json_schema,
    manufacturing_feedback_json_schema, manufacturing_feedback_to_sarif,
    parse_manufacturing_feedback, parse_manufacturing_feedback_declaration,
    render_manufacturing_feedback_comparison_summary, render_manufacturing_feedback_summary,
    verify_analysis_manifest_board,
};
use policy_deployment::{
    advance_policy_deployment, parse_policy_deployment_state, policy_deployment_state_json_schema,
    render_policy_deployment_summary,
};
use policy_deployment_rollback::{
    apply_policy_deployment_rollback, parse_policy_deployment_rollback_state,
    parse_signed_policy_deployment_rollback, policy_deployment_rollback_state_json_schema,
    render_policy_deployment_rollback_summary, sign_policy_deployment_rollback,
    signed_policy_deployment_rollback_json_schema,
};
use policy_deployment_verification::{
    parse_policy_deployment_verification, policy_deployment_verification_json_schema,
    render_policy_deployment_verification_summary, verify_policy_deployment,
};
use policy_incident_ledger::{
    append_policy_incident, parse_policy_incident_ledger, policy_incident_ledger_json_schema,
    render_policy_incident_ledger_summary,
};
use policy_lifecycle::{
    append_policy_lifecycle_event, lifecycle_evidence, parse_policy_lifecycle_ledger,
    parse_policy_lifecycle_snapshot, policy_lifecycle_ledger_json_schema,
    policy_lifecycle_snapshot_json_schema, render_policy_lifecycle_summary,
    snapshot_policy_lifecycle,
};
use policy_lifecycle_checkpoint::{
    parse_policy_lifecycle_trust_state, parse_policy_lifecycle_witness_quorum_report,
    parse_signed_policy_lifecycle_checkpoint, parse_signed_policy_lifecycle_checkpoint_witness,
    parse_signed_policy_lifecycle_key_rotation, policy_lifecycle_trust_state_json_schema,
    policy_lifecycle_witness_quorum_json_schema, sign_policy_lifecycle_checkpoint,
    sign_policy_lifecycle_checkpoint_witness, sign_policy_lifecycle_key_rotation,
    signed_policy_lifecycle_checkpoint_json_schema,
    signed_policy_lifecycle_checkpoint_witness_json_schema,
    signed_policy_lifecycle_key_rotation_json_schema, verify_policy_lifecycle_checkpoint,
    verify_policy_lifecycle_checkpoint_witnesses,
};
use policy_pack::{
    OrganizationPolicyPack, PolicyTrustState, SignedPolicyPack, advance_policy_trust_state,
    parse_policy_pack, parse_policy_trust_state, parse_signed_policy_pack, policy_pack_json_schema,
    policy_trust_state_json_schema, sign_policy_pack, signed_policy_pack_json_schema,
    verify_signed_policy_pack,
};
use policy_recommendation::{
    PolicyRecommendationInput, generate_policy_recommendations, parse_policy_recommendation_report,
    policy_recommendation_json_schema, render_policy_recommendation_summary,
};
use policy_remediation::{
    apply_policy_remediation, parse_policy_remediation_state,
    parse_signed_policy_remediation_approval, policy_remediation_state_json_schema,
    render_policy_remediation_summary, sign_policy_remediation_approval,
    signed_policy_remediation_approval_json_schema,
};
use policy_rollback_recovery::{
    PolicyRollbackRecoveryEvidence, close_rollback_incident, parse_policy_rollback_recovery,
    parse_rollback_incident_closure, parse_signed_rollback_incident_acknowledgment,
    policy_rollback_recovery_json_schema, render_policy_rollback_recovery_summary,
    render_rollback_incident_closure_summary, rollback_incident_closure_json_schema,
    sign_rollback_incident_acknowledgment, signed_rollback_incident_acknowledgment_json_schema,
    verify_policy_rollback_recovery,
};
use policy_rollout::{
    CanaryMonitoringInput, RolloutAnalysisInput, RolloutProjectInput,
    canary_monitoring_json_schema, parse_canary_monitoring_report, parse_policy_rollout_report,
    policy_rollout_json_schema, record_canary_monitoring, render_canary_monitoring_summary,
    render_policy_rollout_summary, rollout_candidate_profile, simulate_policy_rollout,
};
use policy_rollout_approval::{
    RolloutApprovalDecision, canary_authorization_json_schema, parse_canary_authorization,
    parse_signed_rollout_approval, render_canary_authorization_summary, sign_rollout_approval,
    signed_rollout_approval_json_schema, verify_rollout_approvals,
};
use policy_suspension::{
    PolicySuspensionDecision, apply_policy_suspension_decision, enforce_policy_suspensions,
    parse_policy_suspension_state, parse_signed_policy_suspension_decision,
    policy_suspension_state_json_schema, render_policy_suspension_summary,
    sign_policy_suspension_decision, signed_policy_suspension_decision_json_schema,
};
use remote_policy::{fetch_remote_policy_pack, remote_policy_pack_receipt_json_schema};
use remote_witness::{remote_witness_receipt_json_schema, request_remote_witness};

#[derive(Parser)]
#[command(version, about = "Deterministic PCB physical-design engine")]
struct Cli {
    #[command(subcommand)]
    command: Box<Command>,
}

#[derive(Clone, Debug)]
struct CompactPath(Box<Path>);

impl FromStr for CompactPath {
    type Err = Infallible;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(PathBuf::from(value).into_boxed_path()))
    }
}

impl std::ops::Deref for CompactPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Json,
    Sarif,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum HumanDecisionArg {
    Approve,
    Reject,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CanaryCompletionDecisionArg {
    Promote,
    Rollback,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum PolicySuspensionDecisionArg {
    Suspend,
    Continue,
}

impl From<PolicySuspensionDecisionArg> for PolicySuspensionDecision {
    fn from(value: PolicySuspensionDecisionArg) -> Self {
        match value {
            PolicySuspensionDecisionArg::Suspend => Self::Suspend,
            PolicySuspensionDecisionArg::Continue => Self::Continue,
        }
    }
}

impl From<CanaryCompletionDecisionArg> for CanaryCompletionDecision {
    fn from(value: CanaryCompletionDecisionArg) -> Self {
        match value {
            CanaryCompletionDecisionArg::Promote => Self::Promote,
            CanaryCompletionDecisionArg::Rollback => Self::Rollback,
        }
    }
}

impl From<HumanDecisionArg> for HumanEscalationDecision {
    fn from(value: HumanDecisionArg) -> Self {
        match value {
            HumanDecisionArg::Approve => Self::Approve,
            HumanDecisionArg::Reject => Self::Reject,
        }
    }
}

impl From<HumanDecisionArg> for RolloutApprovalDecision {
    fn from(value: HumanDecisionArg) -> Self {
        match value {
            HumanDecisionArg::Approve => Self::Approve,
            HumanDecisionArg::Reject => Self::Reject,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ApprovalArtifactKindArg {
    SignedAiApproval,
    AiQuorumReport,
    SignedHumanEscalation,
    HumanEscalationReport,
    SignedPolicyPack,
}

impl From<ApprovalArtifactKindArg> for ApprovalArtifactKind {
    fn from(value: ApprovalArtifactKindArg) -> Self {
        match value {
            ApprovalArtifactKindArg::SignedAiApproval => Self::SignedAiApproval,
            ApprovalArtifactKindArg::AiQuorumReport => Self::AiQuorumReport,
            ApprovalArtifactKindArg::SignedHumanEscalation => Self::SignedHumanEscalation,
            ApprovalArtifactKindArg::HumanEscalationReport => Self::HumanEscalationReport,
            ApprovalArtifactKindArg::SignedPolicyPack => Self::SignedPolicyPack,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum AiQuorumArtifact {
    SessionRouted(SessionRoutedAiApprovalQuorumReport),
    Session(SessionAiApprovalQuorumReport),
    Routed(RoutedAiApprovalQuorumReport),
    Global(AiApprovalQuorumReport),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum QualityFormat {
    Json,
    Sarif,
}

#[derive(Debug, Serialize)]
struct DoctorCheck {
    id: &'static str,
    required: bool,
    available: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    schema_version: u32,
    engine: &'static str,
    engine_version: &'static str,
    ready: bool,
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
struct CapabilityCommand {
    name: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct CapabilitiesReport {
    schema_version: u32,
    engine: &'static str,
    engine_version: &'static str,
    board_schema_version: u32,
    commands: Vec<CapabilityCommand>,
    fabrication_profiles: Vec<String>,
    external_integrations: Vec<&'static str>,
    output_contracts: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct InputDescriptor {
    path: String,
    bytes: usize,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct AnalysisConfiguration {
    rules: Rules,
    project_settings_loaded: bool,
    applied_custom_rules: usize,
    dfm_profile: Option<DfmProfile>,
    organization_policy_pack: Option<String>,
}

#[derive(Debug, Serialize)]
struct AnalysisResult {
    clean: bool,
    violations: usize,
    routed_nets: usize,
    unrouted_nets: usize,
    total_length_nm: i64,
    total_vias: usize,
}

#[derive(Debug, Serialize)]
struct RunManifest {
    schema_version: u32,
    engine: String,
    engine_version: String,
    command: String,
    input: InputDescriptor,
    project: Option<InputDescriptor>,
    rules_file: Option<InputDescriptor>,
    dfm_profile_file: Option<InputDescriptor>,
    policy_pack_file: Option<InputDescriptor>,
    configuration: AnalysisConfiguration,
    result: AnalysisResult,
    artifacts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ComparisonInputs {
    quality: InputDescriptor,
    checks: InputDescriptor,
}

#[derive(Debug, Serialize)]
struct ComparisonManifest {
    schema_version: u32,
    engine: String,
    engine_version: String,
    command: String,
    baseline: ComparisonInputs,
    current: ComparisonInputs,
    regression: bool,
    artifacts: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Print the versioned machine-readable capability inventory.
    Capabilities {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Diagnose the pcbex installation and optional external integrations.
    Doctor {
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Treat a missing or unusable kicad-cli installation as an error.
        #[arg(long)]
        require_kicad: bool,
    },
    /// Generate shell completion definitions on standard output.
    Completion {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Serve pcbex tools over newline-delimited MCP JSON-RPC on stdio.
    McpServer,
    /// Print the current board JSON Schema.
    Schema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed schematic electrical-IR JSON Schema.
    SchematicSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed schematic semantic-diff JSON Schema.
    SchematicDiffSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed schematic reviewer-routing policy JSON Schema.
    SchematicReviewerRoutingPolicySchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed deterministic reviewer-routing plan JSON Schema.
    SchematicReviewerRoutingPlanSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Normalize a KiCad schematic into the versioned electrical-design IR.
    ImportSchematic {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail after writing the IR when buses or hierarchy prevent complete coverage.
        #[arg(long)]
        require_complete: bool,
    },
    /// Compare two KiCad schematics by electrical intent instead of text layout.
    CompareSchematics {
        baseline: PathBuf,
        current: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        sarif_output: Option<PathBuf>,
        /// Fail after writing reports when electrical review is required.
        #[arg(long)]
        require_no_review: bool,
    },
    /// Route semantic schematic changes to policy-selected AI reviewer profiles.
    RouteSchematicReview {
        baseline: PathBuf,
        current: PathBuf,
        #[arg(long)]
        routing_policy: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after writing reports when review is required but no route was produced.
        #[arg(long)]
        require_routed: bool,
    },
    /// Print the closed deterministic electrical-policy JSON Schema.
    ElectricalPolicySchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed deterministic electrical-review JSON Schema.
    ElectricalReviewSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed electrical-review comparison JSON Schema.
    ElectricalReviewComparisonSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed electrical-rule explanation JSON Schema.
    ElectricalExplanationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed electrical waiver-set JSON Schema.
    ElectricalWaiverSetSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed electrical waiver-report JSON Schema.
    ElectricalWaiverReportSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the complete built-in electrical approval policy.
    ElectricalPolicy {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Run deterministic electrical checks and emit an approval report.
    CheckSchematic {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Write a policy-bound explanation for every electrical rule.
        #[arg(long, value_name = "PATH")]
        explain: Option<PathBuf>,
        /// Write a JUnit XML testsuite with one testcase per electrical rule.
        #[arg(long, value_name = "PATH")]
        junit_output: Option<PathBuf>,
        /// Write SARIF 2.1.0 findings for code-scanning integrations.
        #[arg(long, value_name = "PATH")]
        sarif_output: Option<PathBuf>,
        /// Override built-in rule enablement and severities with a JSON policy.
        #[arg(long, conflicts_with = "policy_pack")]
        policy: Option<PathBuf>,
        /// Apply the electrical policy from an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with = "policy")]
        policy_pack: Option<PathBuf>,
        /// Fail after writing the report when error-severity findings remain.
        #[arg(long)]
        require_approved: bool,
    },
    /// Compare current electrical findings with an accepted baseline.
    CompareElectricalReviews {
        baseline: PathBuf,
        current: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail after writing the report when a new or escalated error is found.
        #[arg(long)]
        require_no_new_errors: bool,
    },
    /// Apply explicit, expiring waivers to a deterministic electrical review.
    ApplyElectricalWaivers {
        electrical_review: PathBuf,
        waiver_set: PathBuf,
        /// Explicit deterministic evaluation date in YYYY-MM-DD form.
        #[arg(long)]
        as_of: String,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail after writing the report when unwaived errors remain.
        #[arg(long)]
        require_approved: bool,
    },
    /// Print the closed simulation-declaration JSON Schema.
    SimulationDeclarationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed bound-simulation-evidence JSON Schema.
    SimulationEvidenceSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed fabrication feedback declaration JSON Schema.
    ManufacturingFeedbackDeclarationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed, digest-bound manufacturing feedback JSON Schema.
    ManufacturingFeedbackSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed manufacturing feedback comparison JSON Schema.
    ManufacturingFeedbackComparisonSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed governed manufacturing-policy recommendation JSON Schema.
    PolicyRecommendationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a governed manufacturing-policy recommendation.
    ValidatePolicyRecommendation {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed governed policy-rollout simulation JSON Schema.
    PolicyRolloutSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a governed policy-rollout simulation report.
    ValidatePolicyRollout {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed canary-rollout approval JSON Schema.
    SignedRolloutApprovalSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed canary-rollout authorization JSON Schema.
    CanaryRolloutAuthorizationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed canary-rollout approval.
    ValidateRolloutApproval {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a canary-rollout authorization.
    ValidateCanaryRolloutAuthorization {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed canary monitoring-evidence JSON Schema.
    CanaryMonitoringSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize retained canary monitoring evidence.
    ValidateCanaryMonitoring {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed canary-completion decision JSON Schema.
    SignedCanaryCompletionSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed canary-completion quorum JSON Schema.
    CanaryCompletionSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed canary-completion decision.
    ValidateCanaryCompletionDecision {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a canary-completion quorum report.
    ValidateCanaryCompletion {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed monotonic policy-deployment state JSON Schema.
    PolicyDeploymentStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a monotonic policy-deployment state.
    ValidatePolicyDeploymentState {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed digest-bound post-deployment verification JSON Schema.
    PolicyDeploymentVerificationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize retained post-deployment verification evidence.
    ValidatePolicyDeploymentVerification {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed production-rollback approval JSON Schema.
    SignedPolicyDeploymentRollbackSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed production-rollback approval.
    ValidatePolicyDeploymentRollbackApproval {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed dual-control production-rollback state JSON Schema.
    PolicyDeploymentRollbackStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a retained production-rollback state.
    ValidatePolicyDeploymentRollbackState {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed post-rollback fleet recovery JSON Schema.
    PolicyRollbackRecoverySchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize retained post-rollback recovery evidence.
    ValidatePolicyRollbackRecovery {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed rollback-incident acknowledgment JSON Schema.
    SignedRollbackIncidentAcknowledgmentSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed rollback-incident acknowledgment.
    ValidateRollbackIncidentAcknowledgment {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed rollback-incident closure JSON Schema.
    RollbackIncidentClosureSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a retained rollback-incident closure.
    ValidateRollbackIncidentClosure {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed append-only policy-incident-ledger JSON Schema.
    PolicyIncidentLedgerSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize an append-only policy-incident ledger.
    ValidatePolicyIncidentLedger {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed policy-suspension decision JSON Schema.
    SignedPolicySuspensionDecisionSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed policy-suspension decision.
    ValidatePolicySuspensionDecision {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed policy-suspension state JSON Schema.
    PolicySuspensionStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a retained policy-suspension state.
    ValidatePolicySuspensionState {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed policy-remediation approval JSON Schema.
    SignedPolicyRemediationApprovalSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed policy-remediation approval.
    ValidatePolicyRemediationApproval {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed verified policy-remediation state JSON Schema.
    PolicyRemediationStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a retained policy-remediation state.
    ValidatePolicyRemediationState {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed append-only policy lifecycle ledger JSON Schema.
    PolicyLifecycleLedgerSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize an append-only policy lifecycle ledger.
    ValidatePolicyLifecycleLedger {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed historical policy lifecycle snapshot JSON Schema.
    PolicyLifecycleSnapshotSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a historical policy lifecycle snapshot.
    ValidatePolicyLifecycleSnapshot {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed policy-lifecycle checkpoint JSON Schema.
    SignedPolicyLifecycleCheckpointSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed policy-lifecycle checkpoint.
    ValidatePolicyLifecycleCheckpoint {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed monotonic policy-lifecycle trust-state JSON Schema.
    PolicyLifecycleTrustStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a retained policy-lifecycle trust state.
    ValidatePolicyLifecycleTrustState {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed dual-signed lifecycle key-rotation JSON Schema.
    SignedPolicyLifecycleKeyRotationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a dual-signed lifecycle key rotation.
    ValidatePolicyLifecycleKeyRotation {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed lifecycle-checkpoint witness JSON Schema.
    SignedPolicyLifecycleCheckpointWitnessSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a signed lifecycle-checkpoint witness.
    ValidatePolicyLifecycleCheckpointWitness {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed lifecycle-checkpoint witness-quorum JSON Schema.
    PolicyLifecycleWitnessQuorumSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize a lifecycle-checkpoint witness-quorum report.
    ValidatePolicyLifecycleWitnessQuorum {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Bind fabrication findings and raw evidence to an exact analyzed board.
    RecordManufacturingFeedback {
        declaration: PathBuf,
        #[arg(long)]
        analysis_dir: PathBuf,
        #[arg(long)]
        board: PathBuf,
        /// Raw fabrication or inspection artifact to hash; repeat for each file.
        #[arg(long = "artifact", required = true)]
        artifacts: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        sarif_output: Option<PathBuf>,
        /// Fail after writing evidence unless fabrication feedback passes.
        #[arg(long)]
        require_passed: bool,
    },
    /// Compare accepted manufacturing feedback with a new fabrication result.
    CompareManufacturingFeedback {
        baseline: PathBuf,
        current: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        sarif_output: Option<PathBuf>,
        /// Fail after writing all reports when new or escalated findings regress.
        #[arg(long)]
        fail_on_regressions: bool,
    },
    /// Propose safety-direction DFM tightening from independently bound fabrication evidence.
    RecommendPolicy {
        /// Exact organization policy pack whose DFM profile was used for every analysis.
        policy_pack: PathBuf,
        /// Bound manufacturing feedback; repeat and pair by position with analysis-manifest.
        #[arg(long = "feedback", required = true)]
        feedback: Vec<PathBuf>,
        /// Exact run.json bound by the paired feedback record.
        #[arg(long = "analysis-manifest", required = true)]
        analysis_manifests: Vec<PathBuf>,
        /// Deterministic report date in YYYY-MM-DD form.
        #[arg(long)]
        generated_on: String,
        /// Independent feedback IDs required before proposing one rule change.
        #[arg(long, default_value_t = 2)]
        minimum_occurrences: u32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
    },
    /// Materialize the simulation-only DFM profile bound to a recommendation.
    PolicyRolloutProfile {
        policy_pack: PathBuf,
        recommendation: PathBuf,
        #[arg(long)]
        generated_on: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Compare baseline and candidate analyses across projects before policy rollout.
    SimulatePolicyRollout {
        policy_pack: PathBuf,
        recommendation: PathBuf,
        /// Stable project ID; repeat and pair by position with both analysis directories.
        #[arg(long = "project-id", required = true)]
        project_ids: Vec<String>,
        /// Exact board file bound by both analyses; repeat in project-ID order.
        #[arg(long = "board", required = true)]
        boards: Vec<PathBuf>,
        /// Analysis directories produced with the exact organization policy pack.
        #[arg(long = "baseline-analysis", required = true)]
        baseline_analyses: Vec<PathBuf>,
        /// Analysis directories produced with the simulation-only candidate profile.
        #[arg(long = "candidate-analysis", required = true)]
        candidate_analyses: Vec<PathBuf>,
        #[arg(long)]
        generated_on: String,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
    },
    /// Sign one human decision over an exact rollout simulation and canary scope.
    SignRolloutApproval {
        rollout: PathBuf,
        #[arg(long = "canary-project", required = true)]
        canary_projects: Vec<String>,
        #[arg(long)]
        valid_from_unix: u64,
        #[arg(long)]
        expires_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long, value_enum)]
        decision: HumanDecisionArg,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify dual-control approval and issue a bounded, rollback-safe canary authorization.
    VerifyRolloutApprovals {
        rollout: PathBuf,
        #[arg(long)]
        policy_pack: PathBuf,
        #[arg(long = "approval", required = true)]
        approvals: Vec<PathBuf>,
        #[arg(long)]
        evaluated_at_unix: u64,
        #[arg(long, default_value_t = 2)]
        minimum_approvals: u32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_authorized: bool,
    },
    /// Compare authorized canary observations with the exact simulated baselines.
    RecordCanaryMonitoring {
        rollout: PathBuf,
        authorization: PathBuf,
        #[arg(long = "project-id", required = true)]
        project_ids: Vec<String>,
        #[arg(long = "board", required = true)]
        boards: Vec<PathBuf>,
        #[arg(long = "baseline-analysis", required = true)]
        baseline_analyses: Vec<PathBuf>,
        #[arg(long = "observed-analysis", required = true)]
        observed_analyses: Vec<PathBuf>,
        #[arg(long)]
        observed_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_passed: bool,
    },
    /// Sign an explicit promotion or rollback decision over exact monitoring evidence.
    SignCanaryCompletion {
        rollout: PathBuf,
        monitoring: PathBuf,
        authorization: PathBuf,
        #[arg(long, value_enum)]
        decision: CanaryCompletionDecisionArg,
        #[arg(long)]
        decided_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify trusted dual-control signatures and finalize promotion or rollback.
    VerifyCanaryCompletion {
        rollout: PathBuf,
        monitoring: PathBuf,
        authorization: PathBuf,
        #[arg(long)]
        policy_pack: PathBuf,
        #[arg(long = "decision", required = true)]
        decisions: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_decisions: u32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_finalized: bool,
    },
    /// Apply a finalized decision to a hash-chained monotonic deployment state.
    AdvancePolicyDeployment {
        rollout: PathBuf,
        monitoring: PathBuf,
        authorization: PathBuf,
        #[arg(long)]
        policy_pack: PathBuf,
        #[arg(long)]
        candidate_policy_pack: PathBuf,
        #[arg(long)]
        source_policy_trust_state: PathBuf,
        #[arg(long)]
        candidate_policy_trust_state: PathBuf,
        #[arg(long = "decision", required = true)]
        decisions: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_decisions: u32,
        /// Previously retained deployment state; required for rollback.
        #[arg(long)]
        baseline_state: Option<PathBuf>,
        /// Retained suspension decisions that deny exact candidate digests.
        #[arg(long = "suspension-state")]
        suspension_states: Vec<PathBuf>,
        /// Independently approved clean successor evidence for suspended policies.
        #[arg(long = "remediation-state")]
        remediation_states: Vec<PathBuf>,
        /// Append-only lifecycle ledgers containing complete suspension/remediation evidence.
        #[arg(long = "policy-lifecycle-ledger")]
        policy_lifecycle_ledgers: Vec<PathBuf>,
        #[arg(long)]
        recorded_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after retaining state unless the candidate became active.
        #[arg(long)]
        require_promotion: bool,
    },
    /// Verify the complete deployed fleet against exact pre-deployment evidence.
    VerifyPolicyDeployment {
        deployment: PathBuf,
        rollout: PathBuf,
        #[arg(long)]
        candidate_policy_pack: PathBuf,
        #[arg(long = "project-id", required = true)]
        project_ids: Vec<String>,
        #[arg(long = "board", required = true)]
        boards: Vec<PathBuf>,
        #[arg(long = "expected-analysis", required = true)]
        expected_analyses: Vec<PathBuf>,
        #[arg(long = "observed-analysis", required = true)]
        observed_analyses: Vec<PathBuf>,
        #[arg(long)]
        verified_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after retaining evidence unless the deployment is verified.
        #[arg(long)]
        require_passed: bool,
    },
    /// Sign an explicit rollback approval over failed production verification.
    SignPolicyDeploymentRollback {
        deployment: PathBuf,
        verification: PathBuf,
        #[arg(long)]
        approved_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Apply a verification-bound rollback after a trusted dual-control quorum.
    ApplyPolicyDeploymentRollback {
        deployment: PathBuf,
        verification: PathBuf,
        #[arg(long)]
        active_policy_pack: PathBuf,
        #[arg(long = "approval", required = true)]
        approvals: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_approvals: u32,
        #[arg(long)]
        recorded_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_applied: bool,
    },
    /// Verify the restored fleet against exact pre-promotion production evidence.
    VerifyPolicyRollbackRecovery {
        rollback: PathBuf,
        rollout: PathBuf,
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        failed_verification: PathBuf,
        #[arg(long)]
        previous_deployment: PathBuf,
        #[arg(long)]
        baseline_verification: PathBuf,
        #[arg(long)]
        restored_policy_pack: PathBuf,
        #[arg(long = "project-id", required = true)]
        project_ids: Vec<String>,
        #[arg(long = "board", required = true)]
        boards: Vec<PathBuf>,
        #[arg(long = "expected-analysis", required = true)]
        expected_analyses: Vec<PathBuf>,
        #[arg(long = "observed-analysis", required = true)]
        observed_analyses: Vec<PathBuf>,
        #[arg(long)]
        verified_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after retaining evidence unless recovery is complete and clean.
        #[arg(long)]
        require_passed: bool,
    },
    /// Sign an operator acknowledgment over exact clean recovery evidence.
    SignRollbackIncidentAcknowledgment {
        rollback: PathBuf,
        recovery: PathBuf,
        #[arg(long)]
        acknowledged_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        operator_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Close a rollback incident after clean recovery and independent acknowledgment.
    CloseRollbackIncident {
        rollback: PathBuf,
        recovery: PathBuf,
        #[arg(long)]
        restored_policy_pack: PathBuf,
        #[arg(long)]
        acknowledgment: PathBuf,
        #[arg(long)]
        closed_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_closed: bool,
    },
    /// Append one closed rollback incident and recompute bounded operational metrics.
    AppendPolicyIncidentLedger {
        rollback: PathBuf,
        #[arg(long)]
        failed_verification: PathBuf,
        #[arg(long)]
        recovery: PathBuf,
        #[arg(long)]
        closure: PathBuf,
        #[arg(long)]
        baseline_ledger: Option<PathBuf>,
        #[arg(long, default_value_t = 2)]
        suspension_threshold: u32,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after writing when repeated incidents require human suspension review.
        #[arg(long)]
        require_no_suspension_review: bool,
    },
    /// Sign a suspend/continue decision over one repeated-incident candidate.
    SignPolicySuspensionDecision {
        ledger: PathBuf,
        #[arg(long)]
        failed_revision: u32,
        #[arg(long)]
        failed_policy_pack_sha256: String,
        #[arg(long, value_enum)]
        decision: PolicySuspensionDecisionArg,
        #[arg(long)]
        decided_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Apply a trusted unanimous quorum and retain an exact-digest suspension state.
    ApplyPolicySuspensionDecision {
        ledger: PathBuf,
        #[arg(long)]
        policy_pack: PathBuf,
        #[arg(long)]
        failed_revision: u32,
        #[arg(long)]
        failed_policy_pack_sha256: String,
        #[arg(long = "decision", required = true)]
        decisions: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_decisions: u32,
        #[arg(long)]
        recorded_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_suspended: bool,
    },
    /// Sign an independent approval over a clean successor remediation candidate.
    SignPolicyRemediationApproval {
        suspension: PathBuf,
        candidate_policy_pack: PathBuf,
        candidate_policy_trust_state: PathBuf,
        rollout: PathBuf,
        monitoring: PathBuf,
        #[arg(long)]
        approved_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify independent approvals and lift one suspension for one exact successor digest.
    ApplyPolicyRemediation {
        suspension: PathBuf,
        #[arg(long)]
        policy_pack: PathBuf,
        #[arg(long)]
        candidate_policy_pack: PathBuf,
        #[arg(long)]
        candidate_policy_trust_state: PathBuf,
        #[arg(long)]
        rollout: PathBuf,
        #[arg(long)]
        monitoring: PathBuf,
        #[arg(long = "approval", required = true)]
        approvals: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_approvals: u32,
        #[arg(long)]
        recorded_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        #[arg(long)]
        require_verified: bool,
    },
    /// Append one complete suspension decision or remediation to its immutable lifecycle.
    AppendPolicyLifecycleEvent {
        /// Previously retained lifecycle ledger; required after the first event.
        #[arg(long)]
        baseline_ledger: Option<PathBuf>,
        /// Complete signed suspension/continue state to append.
        #[arg(long, conflicts_with = "remediation")]
        suspension: Option<PathBuf>,
        /// Complete independently verified remediation state to append.
        #[arg(long, conflicts_with = "suspension")]
        remediation: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after writing while any suspension is awaiting remediation.
        #[arg(long)]
        require_no_pending_suspensions: bool,
    },
    /// Recompute policy suspension/remediation status at one historical generation.
    SnapshotPolicyLifecycle {
        ledger: PathBuf,
        #[arg(long)]
        generation: u64,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Sign the exact head and normalized digest of an append-only lifecycle ledger.
    SignPolicyLifecycleCheckpoint {
        ledger: PathBuf,
        #[arg(long)]
        issued_at_unix: u64,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify a checkpoint and monotonically advance retained lifecycle trust.
    VerifyPolicyLifecycleCheckpoint {
        ledger: PathBuf,
        checkpoint: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        /// Previously accepted state used to reject rollback, equivocation, and forks.
        #[arg(long)]
        baseline_state: Option<PathBuf>,
        /// Dual-signed old-to-new key transition required when the signer key changes.
        #[arg(long, requires = "baseline_state")]
        key_rotation: Option<PathBuf>,
        #[arg(long)]
        accepted_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail unless the checkpoint is accepted (useful for CI policy gates).
        #[arg(long)]
        require_accepted: bool,
    },
    /// Authorize one exact lifecycle signing-key transition with both old and new keys.
    SignPolicyLifecycleKeyRotation {
        baseline_state: PathBuf,
        #[arg(long)]
        old_private_key: PathBuf,
        #[arg(long)]
        new_private_key: PathBuf,
        #[arg(long)]
        rotated_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Independently witness one exact accepted lifecycle checkpoint.
    WitnessPolicyLifecycleCheckpoint {
        trust_state: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        witness_id: String,
        #[arg(long)]
        observed_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify distinct trusted lifecycle witnesses and evaluate their quorum.
    VerifyPolicyLifecycleCheckpointWitnesses {
        trust_state: PathBuf,
        #[arg(long = "witness", required = true)]
        witnesses: Vec<PathBuf>,
        #[arg(long = "public-key", required = true)]
        public_keys: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_witnesses: u32,
        #[arg(long)]
        evaluated_at_unix: u64,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        require_quorum: bool,
    },
    /// Bind simulation assertions and raw artifacts to an electrical review.
    RecordSimulationEvidence {
        declaration: PathBuf,
        #[arg(long)]
        electrical_review: PathBuf,
        /// Raw simulator output to hash and reference by basename.
        #[arg(long = "artifact", required = true)]
        artifacts: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail after writing evidence unless the review and every assertion pass.
        #[arg(long)]
        require_passed: bool,
    },
    /// Print the closed AI schematic-review request JSON Schema.
    AiReviewRequestSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed AI schematic-review response JSON Schema.
    AiReviewResponseSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed AI-approval JSON Schema.
    SignedAiApprovalSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed AI approval-quorum report JSON Schema.
    AiApprovalQuorumSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed profile-aware AI approval-quorum report JSON Schema.
    RoutedAiApprovalQuorumSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed human-escalation JSON Schema.
    SignedHumanEscalationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed human-escalation report JSON Schema.
    HumanEscalationReportSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed append-only approval-transparency-log JSON Schema.
    ApprovalTransparencyLogSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed approval-log checkpoint JSON Schema.
    SignedApprovalLogCheckpointSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed approval-log verification report JSON Schema.
    ApprovalLogVerificationReportSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed approval-log witness JSON Schema.
    SignedApprovalLogWitnessSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed approval-log witness trust-state JSON Schema.
    ApprovalLogWitnessTrustStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed signed witness-key-rotation JSON Schema.
    SignedApprovalLogWitnessKeyRotationSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed approval-log public anchor proof JSON Schema.
    ApprovalLogAnchorProofSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed public anchor verification report JSON Schema.
    ApprovalLogAnchorVerificationReportSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed approval-log witness quorum report JSON Schema.
    ApprovalLogWitnessQuorumReportSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed remote-witness transport receipt JSON Schema.
    RemoteWitnessReceiptSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the closed central policy-registry receipt JSON Schema.
    RemotePolicyPackReceiptSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Prepare a complete, digest-bound request for an AI schematic reviewer.
    PrepareAiReview {
        input: PathBuf,
        #[arg(long)]
        electrical_review: PathBuf,
        #[arg(long, conflicts_with = "policy_pack")]
        policy: Option<PathBuf>,
        #[arg(long = "simulation-evidence")]
        simulation_evidence: Vec<PathBuf>,
        /// Required design intent as `id=text`; repeat for each requirement.
        #[arg(long = "requirement", conflicts_with = "policy_pack")]
        requirements: Vec<String>,
        /// Use electrical policy, requirements, and simulation gate from an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["policy", "requirements", "allow_no_simulation"])]
        policy_pack: Option<PathBuf>,
        /// Permit final approval without any simulation evidence.
        #[arg(long)]
        allow_no_simulation: bool,
        #[arg(short, long)]
        output: PathBuf,
        /// Also create a random time-bound challenge bound to the new request.
        #[arg(long)]
        session_output: Option<CompactPath>,
    },
    /// Create a new Ed25519 keypair without overwriting existing files.
    ApprovalKeygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Evaluate an AI response and sign the resulting approval or rejection.
    SignAiReview {
        request: PathBuf,
        response: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        /// Bind the signature to a time-bound, single-session challenge.
        #[arg(long)]
        session: Option<CompactPath>,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail after writing the signed result unless every gate approves.
        #[arg(long)]
        require_approved: bool,
    },
    /// Strictly verify a signed AI approval against its exact request and response.
    VerifyAiApproval {
        approval: PathBuf,
        request: PathBuf,
        response: PathBuf,
        #[arg(
            long,
            conflicts_with = "policy_pack",
            required_unless_present = "policy_pack"
        )]
        public_key: Option<PathBuf>,
        /// Trust the signer key declared by an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with = "public_key")]
        policy_pack: Option<PathBuf>,
        /// Require a v2 approval bound to this active review session.
        #[arg(long)]
        session: Option<CompactPath>,
        /// Also require the verified envelope to represent an approval.
        #[arg(long)]
        require_approved: bool,
    },
    /// Verify independent signed AI reviews and enforce a multi-reviewer quorum.
    VerifyAiQuorum {
        request: PathBuf,
        /// Signed approval envelope; repeat once per reviewer.
        #[arg(long = "approval", required = true)]
        approvals: Vec<PathBuf>,
        /// Exact AI response paired by position with each --approval.
        #[arg(long = "response", required = true)]
        responses: Vec<PathBuf>,
        /// Organization policy pack containing every trusted approval signer.
        #[arg(long)]
        policy_pack: PathBuf,
        #[arg(long, default_value_t = 2)]
        minimum_approvals: u32,
        #[arg(long, default_value_t = 2)]
        minimum_distinct_providers: u32,
        #[arg(long, default_value_t = 2)]
        minimum_distinct_models: u32,
        /// Accepted baseline schematic used to recompute reviewer routing.
        #[arg(long, requires_all = ["current_schematic", "reviewer_routing_policy"])]
        baseline_schematic: Option<PathBuf>,
        /// Proposed schematic; its normalized digest must match the AI review request.
        #[arg(long, requires_all = ["baseline_schematic", "reviewer_routing_policy"])]
        current_schematic: Option<PathBuf>,
        /// Strict routing policy enabling profile-aware quorum enforcement.
        #[arg(long, requires_all = ["baseline_schematic", "current_schematic"])]
        reviewer_routing_policy: Option<PathBuf>,
        /// Require every approval to bind this active review session.
        #[arg(long)]
        session: Option<CompactPath>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        summary_output: Option<PathBuf>,
        /// Fail after writing reports unless every quorum threshold passes.
        #[arg(long)]
        require_quorum: bool,
    },
    /// Sign a human decision for eligible, time-bound AI needs-human evidence.
    SignHumanEscalation {
        request: CompactPath,
        #[arg(long)]
        session: CompactPath,
        #[arg(long)]
        ai_quorum: CompactPath,
        #[arg(long)]
        private_key: CompactPath,
        #[arg(long)]
        signer_id: String,
        #[arg(long, value_enum)]
        decision: HumanDecisionArg,
        #[arg(long)]
        reason: String,
        #[arg(long)]
        ticket: String,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Verify dual-control human decisions for eligible AI needs-human evidence.
    VerifyHumanEscalation {
        request: CompactPath,
        #[arg(long)]
        session: CompactPath,
        #[arg(long)]
        ai_quorum: CompactPath,
        #[arg(long = "escalation", required = true)]
        escalations: Vec<PathBuf>,
        #[arg(long)]
        policy_pack: CompactPath,
        #[arg(long, default_value_t = 2)]
        minimum_approvals: u32,
        #[arg(short, long)]
        output: CompactPath,
        #[arg(long)]
        summary_output: Option<CompactPath>,
        /// Fail after writing evidence unless dual control approves.
        #[arg(long)]
        require_approved: bool,
    },
    /// Create an empty append-only approval transparency log.
    InitApprovalLog {
        #[arg(long)]
        log_id: String,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Append one normalized approval artifact to a new immutable log snapshot.
    AppendApprovalLog {
        log: CompactPath,
        #[arg(long)]
        artifact: CompactPath,
        #[arg(long, value_enum)]
        kind: ApprovalArtifactKindArg,
        /// Explicit event time for reproducible imports; defaults to the current clock.
        #[arg(long)]
        recorded_at_unix: Option<u64>,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Sign the exact head and complete digest of an approval log.
    SignApprovalLog {
        log: CompactPath,
        #[arg(long)]
        private_key: CompactPath,
        #[arg(long)]
        signer_id: String,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Verify every hash-chain entry and its trusted signed checkpoint.
    VerifyApprovalLog {
        log: CompactPath,
        #[arg(long)]
        checkpoint: CompactPath,
        #[arg(long)]
        public_key: CompactPath,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Independently witness one exact signed approval-log checkpoint.
    WitnessApprovalLog {
        checkpoint: CompactPath,
        #[arg(long)]
        private_key: CompactPath,
        #[arg(long)]
        witness_id: String,
        /// Explicit observation time; defaults to the current clock.
        #[arg(long)]
        observed_at_unix: Option<u64>,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Initialize generation-zero trust for an approval-log witness key.
    InitApprovalLogWitnessTrust {
        #[arg(long)]
        witness_id: String,
        #[arg(long)]
        public_key: CompactPath,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Dual-sign a one-generation witness-key transition with old and new keys.
    SignApprovalLogWitnessKeyRotation {
        trust_state: CompactPath,
        #[arg(long)]
        old_private_key: CompactPath,
        #[arg(long)]
        new_private_key: CompactPath,
        /// Explicit auditable rotation time; defaults to the current clock.
        #[arg(long)]
        rotated_at_unix: Option<u64>,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Verify and apply one witness-key transition without overwriting prior evidence.
    ApplyApprovalLogWitnessKeyRotation {
        trust_state: CompactPath,
        rotation: CompactPath,
        #[arg(short, long)]
        output: CompactPath,
        /// Export the newly trusted key for existing witness-verification interfaces.
        #[arg(long)]
        public_key_output: CompactPath,
    },
    /// Validate trust state and export its current witness public key.
    ExportApprovalLogWitnessPublicKey {
        trust_state: CompactPath,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Build and sign a Merkle inclusion proof as a public-log operator.
    CreateApprovalLogAnchor {
        checkpoint: CompactPath,
        /// Ordered checkpoint snapshot; repeat in exact public-log leaf order.
        #[arg(long = "log-checkpoint", required = true)]
        log_checkpoints: Vec<PathBuf>,
        #[arg(long)]
        leaf_index: u64,
        #[arg(long)]
        log_id: String,
        #[arg(long)]
        private_key: CompactPath,
        /// Explicit tree-head observation time; defaults to the current clock.
        #[arg(long)]
        observed_at_unix: Option<u64>,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Verify checkpoint inclusion under a trusted signed public-log tree head.
    VerifyApprovalLogAnchor {
        checkpoint: CompactPath,
        #[arg(long)]
        proof: CompactPath,
        #[arg(long)]
        public_key: CompactPath,
        #[arg(short, long)]
        output: CompactPath,
    },
    /// Verify independent witnesses over one exact approval-log checkpoint.
    VerifyApprovalLogWitnesses {
        checkpoint: CompactPath,
        #[arg(long = "witness", required = true)]
        witnesses: Vec<PathBuf>,
        /// Trusted public key paired by position with each --witness.
        #[arg(long = "public-key", required = true)]
        public_keys: Vec<PathBuf>,
        #[arg(long, default_value_t = 2)]
        minimum_witnesses: u32,
        #[arg(short, long)]
        output: CompactPath,
        /// Fail after writing the report unless the witness threshold is met.
        #[arg(long)]
        require_quorum: bool,
    },
    /// Request and immediately verify a witness from a bounded HTTPS service.
    RequestApprovalLogWitness {
        checkpoint: CompactPath,
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        public_key: CompactPath,
        /// Environment-variable name containing an optional Bearer token.
        #[arg(long)]
        bearer_token_env: Option<String>,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout_seconds: u64,
        #[arg(short, long)]
        output: CompactPath,
        #[arg(long)]
        receipt_output: CompactPath,
        /// Test-only escape hatch; permits only loopback HTTP.
        #[arg(long, hide = true)]
        allow_http_loopback: bool,
    },
    /// List built-in, revisioned fabrication profiles as JSON.
    DfmProfiles {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Write the strict JSON Schema for distributable external DFM profiles.
    DfmProfileSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize an external DFM profile.
    ValidateDfmProfile {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Write the closed organization policy-pack JSON Schema.
    PolicyPackSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Validate and normalize an organization policy pack.
    ValidatePolicyPack {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Write the closed signed organization policy-pack JSON Schema.
    SignedPolicyPackSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Write the closed monotonic policy trust-state JSON Schema.
    PolicyTrustStateSchema {
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Create an Ed25519 keypair for signing organization policy packs.
    PolicyKeygen {
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
    },
    /// Sign a validated organization policy pack without overwriting output.
    SignPolicyPack {
        input: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        signer_id: String,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify and extract an authenticated organization policy pack.
    VerifyPolicyPack {
        input: PathBuf,
        #[arg(long)]
        public_key: PathBuf,
        /// Previously accepted state used to reject revision rollback and equivocation.
        #[arg(long)]
        baseline_state: Option<PathBuf>,
        /// Write the newly accepted state without overwriting an existing file.
        #[arg(long)]
        state_output: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Fetch and verify a signed policy pack from a bounded HTTPS registry.
    FetchPolicyPack {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        public_key: CompactPath,
        /// Previously accepted state used to reject revision rollback and equivocation.
        #[arg(long)]
        baseline_state: Option<CompactPath>,
        /// Environment-variable name containing an optional Bearer token.
        #[arg(long)]
        bearer_token_env: Option<String>,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout_seconds: u64,
        #[arg(long)]
        signed_output: CompactPath,
        #[arg(short, long)]
        output: CompactPath,
        #[arg(long)]
        state_output: CompactPath,
        #[arg(long)]
        receipt_output: CompactPath,
        /// Test-only escape hatch; permits only loopback HTTP.
        #[arg(long, hide = true)]
        allow_http_loopback: bool,
    },
    /// Upgrade an older board JSON document to the current schema.
    Migrate {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    Route {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        svg: Option<PathBuf>,
        #[arg(long)]
        allow_unrouted: bool,
    },
    /// Generate Pareto-ranked N-best routes for a board JSON document.
    RouteCandidates {
        input: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 5)]
        candidates: usize,
        #[arg(long, default_value_t = 4)]
        workers: usize,
        #[arg(long, default_value_t = 2)]
        router_workers: usize,
        #[arg(long)]
        allow_unrouted: bool,
    },
    /// Reroute only violating or explicitly selected nets; keep all others locked.
    Repair {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Net ID to repair. Repeat for multiple nets; omit to use checker violations.
        #[arg(long = "net-id")]
        net_ids: Vec<u32>,
        #[arg(long)]
        svg: Option<PathBuf>,
    },
    /// Report routing quality and optionally fail on thresholds or regressions.
    Quality {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = QualityFormat::Json)]
        format: QualityFormat,
        /// Previous JSON quality report; increases fail the command.
        #[arg(long)]
        baseline: Option<PathBuf>,
        #[arg(long)]
        max_total_length_nm: Option<i64>,
        #[arg(long)]
        max_vias: Option<usize>,
        #[arg(long)]
        max_unrouted: Option<usize>,
    },
    /// Analyze a KiCad board and emit a reproducible CI artifact bundle.
    AnalyzeKicad {
        input: PathBuf,
        /// KiCad project settings. Defaults to the input's sibling `.kicad_pro` when present.
        #[arg(long)]
        project: Option<PathBuf>,
        /// KiCad custom design rules. Defaults to the input's sibling `.kicad_dru`.
        #[arg(long)]
        rules_file: Option<PathBuf>,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 0.25)]
        grid_mm: f64,
        #[arg(long, default_value_t = 0.25)]
        width_mm: f64,
        #[arg(long, default_value_t = 0.20)]
        clearance_mm: f64,
        #[arg(long, default_value_t = 0.60)]
        via_diameter_mm: f64,
        #[arg(long, default_value_t = 0.30)]
        via_drill_mm: f64,
        #[arg(long, default_value_t = 5)]
        bend_cost: u32,
        #[arg(long, default_value_t = 20)]
        via_cost: u32,
        /// Built-in fabrication profile ID or stable alias.
        #[arg(long, conflicts_with_all = ["fab_profile", "policy_pack"])]
        fab: Option<String>,
        /// Strict external DFM profile JSON.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "policy_pack"])]
        fab_profile: Option<PathBuf>,
        /// Apply the DFM profile from an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "fab_profile"])]
        policy_pack: Option<PathBuf>,
        /// Write all reports before exiting unsuccessfully on violations.
        #[arg(long)]
        fail_on_violations: bool,
    },
    /// Compare two `analyze-kicad` bundles and emit CI-ready deltas.
    CompareAnalysis {
        baseline_dir: PathBuf,
        current_dir: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        /// Write all comparison artifacts before exiting unsuccessfully.
        #[arg(long)]
        fail_on_regressions: bool,
    },
    /// Route a placed KiCad board across its declared copper layers.
    RouteKicad {
        input: PathBuf,
        /// KiCad project settings. Defaults to the input's sibling `.kicad_pro` when present.
        #[arg(long)]
        project: Option<PathBuf>,
        /// KiCad custom design rules. Defaults to the input's sibling `.kicad_dru`.
        #[arg(long)]
        rules_file: Option<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0.25)]
        grid_mm: f64,
        #[arg(long, default_value_t = 0.25)]
        width_mm: f64,
        #[arg(long, default_value_t = 0.20)]
        clearance_mm: f64,
        #[arg(long, default_value_t = 0.60)]
        via_diameter_mm: f64,
        #[arg(long, default_value_t = 0.30)]
        via_drill_mm: f64,
        #[arg(long, default_value_t = 5)]
        bend_cost: u32,
        #[arg(long, default_value_t = 20)]
        via_cost: u32,
        /// Built-in fabrication profile ID or stable alias.
        #[arg(long, conflicts_with_all = ["fab_profile", "policy_pack"])]
        fab: Option<String>,
        /// Strict external DFM profile JSON.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "policy_pack"])]
        fab_profile: Option<PathBuf>,
        /// Apply the DFM profile from an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "fab_profile"])]
        policy_pack: Option<PathBuf>,
        #[arg(long)]
        svg: Option<PathBuf>,
        /// Also write routed items as JSON for the KiCad IPC adapter.
        #[arg(long)]
        json_output: Option<PathBuf>,
        /// Run `kicad-cli pcb drc` after writing the board.
        #[arg(long)]
        drc: bool,
        #[arg(long)]
        allow_unrouted: bool,
    },
    /// Generate Pareto-ranked N-best routes directly from a placed KiCad board.
    RouteKicadCandidates {
        input: PathBuf,
        #[arg(long)]
        project: Option<PathBuf>,
        #[arg(long)]
        rules_file: Option<PathBuf>,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 0.25)]
        grid_mm: f64,
        #[arg(long, default_value_t = 0.25)]
        width_mm: f64,
        #[arg(long, default_value_t = 0.20)]
        clearance_mm: f64,
        #[arg(long, default_value_t = 0.60)]
        via_diameter_mm: f64,
        #[arg(long, default_value_t = 0.30)]
        via_drill_mm: f64,
        #[arg(long, default_value_t = 5)]
        bend_cost: u32,
        #[arg(long, default_value_t = 20)]
        via_cost: u32,
        #[arg(long, conflicts_with_all = ["fab_profile", "policy_pack"])]
        fab: Option<String>,
        /// Strict external DFM profile JSON.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "policy_pack"])]
        fab_profile: Option<PathBuf>,
        /// Apply the DFM profile from an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "fab_profile"])]
        policy_pack: Option<PathBuf>,
        #[arg(long, default_value_t = 5)]
        candidates: usize,
        #[arg(long, default_value_t = 4)]
        workers: usize,
        #[arg(long, default_value_t = 2)]
        router_workers: usize,
        #[arg(long)]
        allow_unrouted: bool,
    },
    Check {
        input: PathBuf,
    },
    /// Run configured manufacturing checks and optionally write a JSON report.
    Dfm {
        input: PathBuf,
        /// Override embedded manufacturing rules with a built-in profile.
        #[arg(long, conflicts_with_all = ["fab_profile", "policy_pack"])]
        fab: Option<String>,
        /// Override embedded manufacturing rules with a strict external DFM profile JSON.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "policy_pack"])]
        fab_profile: Option<PathBuf>,
        /// Override embedded manufacturing rules with an organization policy pack.
        #[arg(long, value_name = "PATH", conflicts_with_all = ["fab", "fab_profile"])]
        policy_pack: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, value_enum, default_value_t = ReportFormat::Json)]
        format: ReportFormat,
    },
    /// Solve trace width from a stackup layer and target impedance.
    ImpedanceWidth {
        input: PathBuf,
        /// Copper layer name, for example F.Cu or In1.Cu.
        #[arg(long)]
        layer: String,
        #[arg(long)]
        target_ohms: f64,
        /// Pair gap in millimetres; when set, solve differential impedance.
        #[arg(long)]
        differential_gap_mm: Option<f64>,
        #[arg(long, default_value_t = 0.01)]
        minimum_width_mm: f64,
        #[arg(long, default_value_t = 5.0)]
        maximum_width_mm: f64,
    },
    /// Report per-segment single-ended and differential impedance as JSON.
    ImpedanceReport {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Previous impedance JSON report; regressions fail the command.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Exit unsuccessfully when geometry, target, or transition violations exist.
        #[arg(long)]
        fail_on_violations: bool,
    },
    Render {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Optimize component placement from a placement JSON document.
    Place {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        iterations: Option<usize>,
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Generate deterministic placement candidates and select from their Pareto front.
    PlaceCandidates {
        input: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 5)]
        candidates: usize,
        #[arg(long, default_value_t = 4)]
        workers: usize,
        #[arg(long)]
        iterations: Option<usize>,
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Optimize footprint placement directly in a KiCad board.
    PlaceKicad {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = 0.5)]
        grid_mm: f64,
        #[arg(long)]
        iterations: Option<usize>,
        #[arg(long)]
        seed: Option<u64>,
        #[arg(long)]
        json_output: Option<PathBuf>,
    },
    /// Generate Pareto-ranked footprint placements directly from a KiCad board.
    PlaceKicadCandidates {
        input: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 0.5)]
        grid_mm: f64,
        #[arg(long, default_value_t = 5)]
        candidates: usize,
        #[arg(long, default_value_t = 4)]
        workers: usize,
        #[arg(long)]
        iterations: Option<usize>,
        #[arg(long)]
        seed: Option<u64>,
    },
    /// Run KiCad DRC and generate Gerber and Excellon manufacturing files.
    Fabricate {
        input: PathBuf,
        #[arg(short, long)]
        output_dir: PathBuf,
    },
}

fn read(path: &PathBuf) -> Result<Board> {
    parse_board_json(
        &fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?,
    )
    .map_err(anyhow::Error::msg)
    .with_context(|| format!("parsing {}", path.display()))
}

fn resolve_dfm_profile(
    name: Option<&str>,
    external: Option<&Path>,
) -> Result<(Option<DfmProfile>, Option<InputDescriptor>)> {
    if let Some(path) = external {
        let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        let source = std::str::from_utf8(&bytes)
            .with_context(|| format!("decoding {} as UTF-8", path.display()))?;
        let profile = parse_external_dfm_profile(source)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("validating external DFM profile {}", path.display()))?;
        return Ok((Some(profile), Some(input_descriptor(path, &bytes))));
    }
    let profile = name
        .map(|name| {
            dfm_profile(name).ok_or_else(|| {
                let available = dfm_profiles()
                    .iter()
                    .map(|profile| profile.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                anyhow::anyhow!(
                    "unknown fabrication profile {name:?}; available profiles: {available}"
                )
            })
        })
        .transpose()?;
    Ok((profile, None))
}

fn load_policy_pack(path: &Path) -> Result<(OrganizationPolicyPack, InputDescriptor)> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let source = std::str::from_utf8(&bytes)
        .with_context(|| format!("decoding {} as UTF-8", path.display()))?;
    let pack = parse_policy_pack(source)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("validating organization policy pack {}", path.display()))?;
    Ok((pack, input_descriptor(path, &bytes)))
}

fn load_signed_policy_pack(path: &Path) -> Result<SignedPolicyPack> {
    let source = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_signed_policy_pack(&source)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("validating signed policy pack {}", path.display()))
}

fn load_policy_trust_state(path: &Path) -> Result<PolicyTrustState> {
    let source = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_policy_trust_state(&source)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("validating policy trust state {}", path.display()))
}

fn validate_ai_request_against_policy_pack(
    request: &AiReviewRequest,
    pack: &OrganizationPolicyPack,
) -> Result<()> {
    if request.electrical_policy != pack.electrical_policy {
        bail!(
            "AI review request electrical policy does not match policy pack {}",
            pack.id
        );
    }
    let mut requirements = pack.ai_requirements.clone();
    requirements.sort_by(|left, right| left.id.cmp(&right.id));
    if request.requirements != requirements {
        bail!(
            "AI review request requirements do not match policy pack {}",
            pack.id
        );
    }
    if request.approval_policy.require_simulation_evidence != pack.require_simulation_evidence {
        bail!(
            "AI review request simulation-evidence policy does not match policy pack {}",
            pack.id
        );
    }
    Ok(())
}

fn executable_check(
    id: &'static str,
    executable: &str,
    version_arguments: &[&str],
    required: bool,
) -> DoctorCheck {
    match ProcessCommand::new(executable)
        .args(version_arguments)
        .output()
    {
        Ok(output) => {
            let rendered = if output.stdout.is_empty() {
                &output.stderr
            } else {
                &output.stdout
            };
            let detail = String::from_utf8_lossy(rendered)
                .lines()
                .next()
                .unwrap_or("version output was empty")
                .trim()
                .to_string();
            DoctorCheck {
                id,
                required,
                available: output.status.success(),
                detail: if output.status.success() {
                    detail
                } else {
                    format!("version command exited with {}: {detail}", output.status)
                },
            }
        }
        Err(error) => DoctorCheck {
            id,
            required,
            available: false,
            detail: error.to_string(),
        },
    }
}

fn doctor_report(require_kicad: bool) -> DoctorReport {
    let current_directory = std::env::current_dir();
    let mut checks = vec![DoctorCheck {
        id: "pcbex",
        required: true,
        available: true,
        detail: format!("pcbex {}", env!("CARGO_PKG_VERSION")),
    }];
    checks.push(match current_directory {
        Ok(path) => DoctorCheck {
            id: "working_directory",
            required: true,
            available: true,
            detail: path.display().to_string(),
        },
        Err(error) => DoctorCheck {
            id: "working_directory",
            required: true,
            available: false,
            detail: error.to_string(),
        },
    });
    checks.push(DoctorCheck {
        id: "fabrication_profiles",
        required: true,
        available: !dfm_profiles().is_empty(),
        detail: format!("{} built-in profile(s)", dfm_profiles().len()),
    });
    checks.push(executable_check(
        "kicad_cli",
        "kicad-cli",
        &["version"],
        require_kicad,
    ));
    checks.push(executable_check("git", "git", &["--version"], false));
    checks.push(executable_check("python", "python3", &["--version"], false));
    let ready = checks
        .iter()
        .all(|check| !check.required || check.available);
    DoctorReport {
        schema_version: 1,
        engine: "pcbex",
        engine_version: env!("CARGO_PKG_VERSION"),
        ready,
        checks,
    }
}

fn capabilities_report() -> CapabilitiesReport {
    let commands = Cli::command()
        .get_subcommands()
        .map(|command| CapabilityCommand {
            name: command.get_name().to_string(),
            description: command
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default(),
        })
        .collect();
    CapabilitiesReport {
        schema_version: 1,
        engine: "pcbex",
        engine_version: env!("CARGO_PKG_VERSION"),
        board_schema_version: CURRENT_SCHEMA_VERSION,
        commands,
        fabrication_profiles: dfm_profiles()
            .iter()
            .map(|profile| profile.id.to_string())
            .collect(),
        external_integrations: vec!["kicad-cli", "kicad-python", "git", "python3", "MCP stdio"],
        output_contracts: vec![
            "JSON Schema",
            "JSON",
            "SARIF 2.1.0",
            "Markdown",
            "SVG",
            "KiCad PCB",
            "Gerber",
            "Excellon",
            "SPDX JSON",
        ],
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match *cli.command {
        Command::Capabilities { output } => {
            let rendered = serde_json::to_string_pretty(&capabilities_report())?;
            if let Some(path) = output {
                fs::write(path, rendered)?;
            } else {
                println!("{rendered}");
            }
        }
        Command::Doctor {
            output,
            require_kicad,
        } => {
            let report = doctor_report(require_kicad);
            let rendered = serde_json::to_string_pretty(&report)?;
            if let Some(path) = output {
                fs::write(path, rendered)?;
            } else {
                println!("{rendered}");
            }
            if !report.ready {
                let failed = report
                    .checks
                    .iter()
                    .filter(|check| check.required && !check.available)
                    .map(|check| check.id)
                    .collect::<Vec<_>>()
                    .join(", ");
                bail!("pcbex installation is not ready: {failed}");
            }
        }
        Command::Completion { shell } => {
            let mut command = Cli::command();
            let name = command.get_name().to_string();
            generate(shell, &mut command, name, &mut io::stdout());
        }
        Command::McpServer => mcp::serve_stdio()?,
        Command::Schema { output } => {
            let schema = serde_json::to_string_pretty(&board_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::SchematicSchema { output } => {
            let schema = serde_json::to_string_pretty(&schematic_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::SchematicDiffSchema { output } => {
            write_or_print_json(&schematic_diff_json_schema(), output.as_ref())?;
        }
        Command::SchematicReviewerRoutingPolicySchema { output } => {
            write_or_print_json(
                &schematic_reviewer_routing_policy_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::SchematicReviewerRoutingPlanSchema { output } => {
            write_or_print_json(
                &schematic_reviewer_routing_plan_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ImportSchematic {
            input,
            output,
            require_complete,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let schematic = import_schematic(&source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", input.display()))?;
            fs::write(&output, serde_json::to_string_pretty(&schematic)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "imported {} symbol(s), {} pin(s), {} net(s); coverage: {}",
                schematic.symbols.len(),
                schematic
                    .symbols
                    .iter()
                    .map(|symbol| symbol.pins.len())
                    .sum::<usize>(),
                schematic.nets.len(),
                if schematic.coverage.complete {
                    "complete"
                } else {
                    "incomplete"
                }
            );
            if require_complete && !schematic.coverage.complete {
                bail!(
                    "schematic coverage is incomplete: {}",
                    schematic
                        .coverage
                        .unsupported_features
                        .iter()
                        .map(|feature| format!("{} ({})", feature.kind, feature.count))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        Command::CompareSchematics {
            baseline,
            current,
            output,
            summary_output,
            sarif_output,
            require_no_review,
        } => {
            require_distinct_outputs(
                [
                    Some(output.as_path()),
                    summary_output.as_deref(),
                    sarif_output.as_deref(),
                ],
                "schematic semantic diff",
            )?;
            let baseline_source = fs::read_to_string(&baseline)
                .with_context(|| format!("reading {}", baseline.display()))?;
            let current_source = fs::read_to_string(&current)
                .with_context(|| format!("reading {}", current.display()))?;
            let baseline_document = import_schematic(&baseline_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", baseline.display()))?;
            let current_document = import_schematic(&current_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", current.display()))?;
            let diff = compare_schematics(&baseline_document, &current_document)
                .map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&diff)?)
                .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = summary_output {
                fs::write(&path, render_schematic_diff_summary(&diff))
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            if let Some(path) = sarif_output {
                fs::write(
                    &path,
                    serde_json::to_string_pretty(&schematic_diff_to_sarif(&diff))?,
                )
                .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "schematic semantic diff: {} affected symbol(s), {} affected net(s); review required {}",
                diff.counts.affected_symbols, diff.counts.affected_nets, diff.review_required
            );
            if require_no_review && diff.review_required {
                bail!("schematic semantic changes require review");
            }
        }
        Command::RouteSchematicReview {
            baseline,
            current,
            routing_policy,
            output,
            summary_output,
            require_routed,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "schematic reviewer routing",
            )?;
            let baseline_source = fs::read_to_string(&baseline)
                .with_context(|| format!("reading {}", baseline.display()))?;
            let current_source = fs::read_to_string(&current)
                .with_context(|| format!("reading {}", current.display()))?;
            let policy_source = fs::read_to_string(&routing_policy)
                .with_context(|| format!("reading {}", routing_policy.display()))?;
            let baseline_document = import_schematic(&baseline_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", baseline.display()))?;
            let current_document = import_schematic(&current_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", current.display()))?;
            let policy = parse_schematic_reviewer_routing_policy(&policy_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("parsing {}", routing_policy.display()))?;
            let plan = route_schematic_review(&baseline_document, &current_document, &policy)
                .map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&plan)?)
                .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = summary_output {
                fs::write(&path, render_schematic_reviewer_routing_summary(&plan))
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "schematic reviewer routing: {} change(s), {} profile(s), {} minimum assignment(s)",
                plan.change_count, plan.route_count, plan.minimum_review_assignments
            );
            if require_routed
                && plan.review_required
                && (!plan.all_changes_routed || plan.routes.is_empty())
            {
                bail!("schematic review is required but every change was not routed");
            }
        }
        Command::ElectricalPolicySchema { output } => {
            let schema = serde_json::to_string_pretty(&electrical_policy_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::ElectricalReviewSchema { output } => {
            let schema = serde_json::to_string_pretty(&electrical_review_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::ElectricalReviewComparisonSchema { output } => {
            write_or_print_json(&electrical_review_comparison_json_schema(), output.as_ref())?;
        }
        Command::ElectricalExplanationSchema { output } => {
            let schema = serde_json::to_string_pretty(&electrical_explanation_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::ElectricalWaiverSetSchema { output } => {
            write_or_print_json(&electrical_waiver_set_json_schema(), output.as_ref())?;
        }
        Command::ElectricalWaiverReportSchema { output } => {
            write_or_print_json(&electrical_waiver_report_json_schema(), output.as_ref())?;
        }
        Command::ElectricalPolicy { output } => {
            let policy = serde_json::to_string_pretty(&ElectricalPolicy::default())?;
            if let Some(path) = output {
                fs::write(path, policy)?;
            } else {
                println!("{policy}");
            }
        }
        Command::CheckSchematic {
            input,
            output,
            explain,
            junit_output,
            sarif_output,
            policy,
            policy_pack,
            require_approved,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let schematic = import_schematic(&source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", input.display()))?;
            let policy = if let Some(path) = policy_pack {
                load_policy_pack(&path)?.0.electrical_policy
            } else if let Some(path) = policy {
                parse_electrical_policy(
                    &fs::read_to_string(&path)
                        .with_context(|| format!("reading {}", path.display()))?,
                )
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("parsing {}", path.display()))?
            } else {
                ElectricalPolicy::default()
            };
            let review = check_schematic(&schematic, &policy).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&review)?)
                .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = explain {
                let explanations =
                    explain_electrical_review(&review, &policy).map_err(anyhow::Error::msg)?;
                fs::write(&path, serde_json::to_string_pretty(&explanations)?)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            if let Some(path) = junit_output {
                let junit =
                    electrical_review_to_junit(&review, &policy).map_err(anyhow::Error::msg)?;
                fs::write(&path, junit).with_context(|| format!("writing {}", path.display()))?;
            }
            if let Some(path) = sarif_output {
                let artifact_uri = input.to_string_lossy();
                let sarif = electrical_review_to_sarif(&review, &policy, &artifact_uri)
                    .map_err(anyhow::Error::msg)?;
                fs::write(&path, serde_json::to_string_pretty(&sarif)?)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "electrical review: {}; {} error(s), {} warning(s), {} info finding(s)",
                if review.approved {
                    "approved"
                } else {
                    "rejected"
                },
                review.counts.errors,
                review.counts.warnings,
                review.counts.info
            );
            if require_approved && !review.approved {
                bail!(
                    "electrical approval rejected by policy {} with {} error(s)",
                    review.policy_id,
                    review.counts.errors
                );
            }
        }
        Command::CompareElectricalReviews {
            baseline,
            current,
            output,
            require_no_new_errors,
        } => {
            let (baseline_review, _) = read_described_json::<ElectricalReview>(&baseline)?;
            let (current_review, _) = read_described_json::<ElectricalReview>(&current)?;
            let comparison = compare_electrical_reviews(&baseline_review, &current_review)
                .map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&comparison)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "electrical baseline comparison: {}; {} new error(s), {} escalated error(s), {} resolved finding(s)",
                if comparison.passed {
                    "no error regressions"
                } else {
                    "error regressions found"
                },
                comparison.counts.new_errors,
                comparison.counts.escalated_errors,
                comparison.resolved_findings.len(),
            );
            if require_no_new_errors && !comparison.passed {
                bail!(
                    "electrical baseline comparison found {} error regression(s)",
                    comparison.counts.error_regressions
                );
            }
        }
        Command::ApplyElectricalWaivers {
            electrical_review,
            waiver_set,
            as_of,
            output,
            require_approved,
        } => {
            let (review, _) = read_described_json::<ElectricalReview>(&electrical_review)?;
            let (waiver_set, _) = read_described_json::<ElectricalWaiverSet>(&waiver_set)?;
            let report = apply_electrical_waivers(&review, &waiver_set, &as_of)
                .map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&report)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "electrical waiver review: {}; {} waived, {} expired, {} remaining error(s)",
                if report.approved {
                    "approved"
                } else {
                    "rejected"
                },
                report.counts.waived,
                report.counts.expired,
                report.counts.remaining_errors
            );
            if require_approved && !report.approved {
                bail!(
                    "electrical waiver review has {} unwaived error(s)",
                    report.counts.remaining_errors
                );
            }
        }
        Command::SimulationDeclarationSchema { output } => {
            let schema = serde_json::to_string_pretty(&simulation_declaration_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::SimulationEvidenceSchema { output } => {
            let schema = serde_json::to_string_pretty(&simulation_evidence_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::ManufacturingFeedbackDeclarationSchema { output } => {
            write_or_print_json(
                &manufacturing_feedback_declaration_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ManufacturingFeedbackSchema { output } => {
            write_or_print_json(&manufacturing_feedback_json_schema(), output.as_ref())?;
        }
        Command::ManufacturingFeedbackComparisonSchema { output } => {
            write_or_print_json(
                &manufacturing_feedback_comparison_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::PolicyRecommendationSchema { output } => {
            write_or_print_json(&policy_recommendation_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyRecommendation { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report = parse_policy_recommendation_report(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::PolicyRolloutSchema { output } => {
            write_or_print_json(&policy_rollout_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyRollout { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report = parse_policy_rollout_report(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::SignedRolloutApprovalSchema { output } => {
            write_or_print_json(&signed_rollout_approval_json_schema(), output.as_ref())?;
        }
        Command::CanaryRolloutAuthorizationSchema { output } => {
            write_or_print_json(&canary_authorization_json_schema(), output.as_ref())?;
        }
        Command::ValidateRolloutApproval { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let approval = parse_signed_rollout_approval(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(approval)?, output.as_ref())?;
        }
        Command::ValidateCanaryRolloutAuthorization { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let authorization = parse_canary_authorization(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(authorization)?, output.as_ref())?;
        }
        Command::CanaryMonitoringSchema { output } => {
            write_or_print_json(&canary_monitoring_json_schema(), output.as_ref())?;
        }
        Command::ValidateCanaryMonitoring { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report = parse_canary_monitoring_report(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::SignedCanaryCompletionSchema { output } => {
            write_or_print_json(&signed_canary_decision_json_schema(), output.as_ref())?;
        }
        Command::CanaryCompletionSchema { output } => {
            write_or_print_json(&canary_completion_json_schema(), output.as_ref())?;
        }
        Command::ValidateCanaryCompletionDecision { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let decision = parse_signed_canary_decision(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(decision)?, output.as_ref())?;
        }
        Command::ValidateCanaryCompletion { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report = parse_canary_completion_report(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::PolicyDeploymentStateSchema { output } => {
            write_or_print_json(&policy_deployment_state_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyDeploymentState { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let state = parse_policy_deployment_state(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(state)?, output.as_ref())?;
        }
        Command::PolicyDeploymentVerificationSchema { output } => {
            write_or_print_json(
                &policy_deployment_verification_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyDeploymentVerification { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report =
                parse_policy_deployment_verification(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::SignedPolicyDeploymentRollbackSchema { output } => {
            write_or_print_json(
                &signed_policy_deployment_rollback_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyDeploymentRollbackApproval { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let approval =
                parse_signed_policy_deployment_rollback(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(approval)?, output.as_ref())?;
        }
        Command::PolicyDeploymentRollbackStateSchema { output } => {
            write_or_print_json(
                &policy_deployment_rollback_state_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyDeploymentRollbackState { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let state =
                parse_policy_deployment_rollback_state(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(state)?, output.as_ref())?;
        }
        Command::PolicyRollbackRecoverySchema { output } => {
            write_or_print_json(&policy_rollback_recovery_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyRollbackRecovery { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report = parse_policy_rollback_recovery(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::SignedRollbackIncidentAcknowledgmentSchema { output } => {
            write_or_print_json(
                &signed_rollback_incident_acknowledgment_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidateRollbackIncidentAcknowledgment { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let acknowledgment = parse_signed_rollback_incident_acknowledgment(&source)
                .map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(acknowledgment)?, output.as_ref())?;
        }
        Command::RollbackIncidentClosureSchema { output } => {
            write_or_print_json(&rollback_incident_closure_json_schema(), output.as_ref())?;
        }
        Command::ValidateRollbackIncidentClosure { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let state = parse_rollback_incident_closure(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(state)?, output.as_ref())?;
        }
        Command::PolicyIncidentLedgerSchema { output } => {
            write_or_print_json(&policy_incident_ledger_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyIncidentLedger { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let ledger = parse_policy_incident_ledger(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(ledger)?, output.as_ref())?;
        }
        Command::SignedPolicySuspensionDecisionSchema { output } => {
            write_or_print_json(
                &signed_policy_suspension_decision_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicySuspensionDecision { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let decision =
                parse_signed_policy_suspension_decision(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(decision)?, output.as_ref())?;
        }
        Command::PolicySuspensionStateSchema { output } => {
            write_or_print_json(&policy_suspension_state_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicySuspensionState { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let state = parse_policy_suspension_state(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(state)?, output.as_ref())?;
        }
        Command::SignedPolicyRemediationApprovalSchema { output } => {
            write_or_print_json(
                &signed_policy_remediation_approval_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyRemediationApproval { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let approval =
                parse_signed_policy_remediation_approval(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(approval)?, output.as_ref())?;
        }
        Command::PolicyRemediationStateSchema { output } => {
            write_or_print_json(&policy_remediation_state_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyRemediationState { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let state = parse_policy_remediation_state(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(state)?, output.as_ref())?;
        }
        Command::PolicyLifecycleLedgerSchema { output } => {
            write_or_print_json(&policy_lifecycle_ledger_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyLifecycleLedger { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let ledger = parse_policy_lifecycle_ledger(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(ledger)?, output.as_ref())?;
        }
        Command::PolicyLifecycleSnapshotSchema { output } => {
            write_or_print_json(&policy_lifecycle_snapshot_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyLifecycleSnapshot { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let snapshot = parse_policy_lifecycle_snapshot(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(snapshot)?, output.as_ref())?;
        }
        Command::SignedPolicyLifecycleCheckpointSchema { output } => {
            write_or_print_json(
                &signed_policy_lifecycle_checkpoint_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyLifecycleCheckpoint { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let checkpoint =
                parse_signed_policy_lifecycle_checkpoint(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(checkpoint)?, output.as_ref())?;
        }
        Command::PolicyLifecycleTrustStateSchema { output } => {
            write_or_print_json(&policy_lifecycle_trust_state_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyLifecycleTrustState { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let state = parse_policy_lifecycle_trust_state(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(state)?, output.as_ref())?;
        }
        Command::SignedPolicyLifecycleKeyRotationSchema { output } => {
            write_or_print_json(
                &signed_policy_lifecycle_key_rotation_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyLifecycleKeyRotation { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let rotation =
                parse_signed_policy_lifecycle_key_rotation(&source).map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(rotation)?, output.as_ref())?;
        }
        Command::SignedPolicyLifecycleCheckpointWitnessSchema { output } => {
            write_or_print_json(
                &signed_policy_lifecycle_checkpoint_witness_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyLifecycleCheckpointWitness { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let witness = parse_signed_policy_lifecycle_checkpoint_witness(&source)
                .map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(witness)?, output.as_ref())?;
        }
        Command::PolicyLifecycleWitnessQuorumSchema { output } => {
            write_or_print_json(
                &policy_lifecycle_witness_quorum_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ValidatePolicyLifecycleWitnessQuorum { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let report = parse_policy_lifecycle_witness_quorum_report(&source)
                .map_err(anyhow::Error::msg)?;
            write_or_print_json(&serde_json::to_value(report)?, output.as_ref())?;
        }
        Command::RecordManufacturingFeedback {
            declaration,
            analysis_dir,
            board,
            artifacts,
            output,
            summary_output,
            sarif_output,
            require_passed,
        } => {
            require_distinct_outputs(
                [
                    Some(output.as_path()),
                    summary_output.as_deref(),
                    sarif_output.as_deref(),
                ],
                "manufacturing feedback",
            )?;
            let declaration_source = fs::read_to_string(&declaration)
                .with_context(|| format!("reading {}", declaration.display()))?;
            let declaration = parse_manufacturing_feedback_declaration(&declaration_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("parsing {}", declaration.display()))?;
            let manifest_path = analysis_dir.join("run.json");
            let manifest_bytes = fs::read(&manifest_path)
                .with_context(|| format!("reading {}", manifest_path.display()))?;
            let board_bytes =
                fs::read(&board).with_context(|| format!("reading {}", board.display()))?;
            let board_sha256 = format!("{:x}", Sha256::digest(&board_bytes));
            verify_analysis_manifest_board(&manifest_bytes, &board_sha256)
                .map_err(anyhow::Error::msg)?;
            if artifacts.len() > 1_000 {
                bail!("manufacturing feedback accepts at most 1000 evidence artifacts");
            }
            let artifact_descriptors = artifacts
                .iter()
                .map(|path| manufacturing_evidence_descriptor(path))
                .collect::<Result<Vec<_>>>()?;
            let feedback = bind_manufacturing_feedback(
                declaration,
                evidence_descriptor("run.json", &manifest_bytes).map_err(anyhow::Error::msg)?,
                evidence_descriptor(&portable_basename(&board)?, &board_bytes)
                    .map_err(anyhow::Error::msg)?,
                artifact_descriptors,
            )
            .map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&feedback)?)
                .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = summary_output {
                fs::write(&path, render_manufacturing_feedback_summary(&feedback))
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            if let Some(path) = sarif_output {
                fs::write(
                    &path,
                    serde_json::to_string_pretty(&manufacturing_feedback_to_sarif(&feedback))?,
                )
                .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "manufacturing feedback {}: {} finding(s), disposition {:?}, passed {}",
                feedback.declaration.id,
                feedback.declaration.findings.len(),
                feedback.declaration.disposition,
                feedback.passed
            );
            if require_passed && !feedback.passed {
                bail!("manufacturing feedback did not pass");
            }
        }
        Command::CompareManufacturingFeedback {
            baseline,
            current,
            output,
            summary_output,
            sarif_output,
            fail_on_regressions,
        } => {
            require_distinct_outputs(
                [
                    Some(output.as_path()),
                    summary_output.as_deref(),
                    sarif_output.as_deref(),
                ],
                "manufacturing feedback comparison",
            )?;
            let baseline_source = fs::read_to_string(&baseline)
                .with_context(|| format!("reading {}", baseline.display()))?;
            let current_source = fs::read_to_string(&current)
                .with_context(|| format!("reading {}", current.display()))?;
            let baseline =
                parse_manufacturing_feedback(&baseline_source).map_err(anyhow::Error::msg)?;
            let current =
                parse_manufacturing_feedback(&current_source).map_err(anyhow::Error::msg)?;
            let comparison =
                compare_manufacturing_feedback(&baseline, &current).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&comparison)?)
                .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = summary_output {
                fs::write(
                    &path,
                    render_manufacturing_feedback_comparison_summary(&comparison),
                )
                .with_context(|| format!("writing {}", path.display()))?;
            }
            if let Some(path) = sarif_output {
                fs::write(
                    &path,
                    serde_json::to_string_pretty(&manufacturing_feedback_comparison_to_sarif(
                        &comparison,
                    ))?,
                )
                .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "manufacturing feedback comparison: {} new, {} escalated, {} resolved; regression {}",
                comparison.new_findings.len(),
                comparison.escalated_findings.len(),
                comparison.resolved_findings.len(),
                comparison.regression
            );
            if fail_on_regressions && comparison.regression {
                bail!("manufacturing feedback comparison found regressions");
            }
        }
        Command::RecommendPolicy {
            policy_pack,
            feedback,
            analysis_manifests,
            generated_on,
            minimum_occurrences,
            output,
            summary_output,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy recommendation",
            )?;
            if feedback.len() != analysis_manifests.len() {
                bail!("policy recommendation requires one analysis manifest per feedback input");
            }
            if feedback.len() > 1_000 {
                bail!("policy recommendation accepts at most 1000 feedback inputs");
            }
            let policy_source = fs::read_to_string(&policy_pack)
                .with_context(|| format!("reading {}", policy_pack.display()))?;
            let policy = parse_policy_pack(&policy_source).map_err(anyhow::Error::msg)?;
            let feedback_documents = feedback
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_manufacturing_feedback(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let manifest_documents = analysis_manifests
                .iter()
                .map(|path| fs::read(path).with_context(|| format!("reading {}", path.display())))
                .collect::<Result<Vec<_>>>()?;
            let inputs = feedback_documents
                .iter()
                .zip(&manifest_documents)
                .map(|(feedback, analysis_manifest)| PolicyRecommendationInput {
                    feedback,
                    analysis_manifest,
                })
                .collect::<Vec<_>>();
            let report = generate_policy_recommendations(
                &policy,
                &inputs,
                &generated_on,
                minimum_occurrences,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            let summary = render_policy_recommendation_summary(&report);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy recommendation: {} proposed tightening(s), {} skipped finding(s); human approval required",
                report.recommendations.len(),
                report.skipped_findings.len()
            );
        }
        Command::PolicyRolloutProfile {
            policy_pack,
            recommendation,
            generated_on,
            output,
        } => {
            let policy = load_policy_pack(&policy_pack)?.0;
            let recommendation_source = fs::read_to_string(&recommendation)
                .with_context(|| format!("reading {}", recommendation.display()))?;
            let recommendation = parse_policy_recommendation_report(&recommendation_source)
                .map_err(anyhow::Error::msg)?;
            let profile = rollout_candidate_profile(&policy, &recommendation, &generated_on)
                .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&profile)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "simulation-only rollout profile written to {}; not deployable",
                output.display()
            );
        }
        Command::SimulatePolicyRollout {
            policy_pack,
            recommendation,
            project_ids,
            boards,
            baseline_analyses,
            candidate_analyses,
            generated_on,
            output,
            summary_output,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy rollout",
            )?;
            if project_ids.len() != boards.len()
                || project_ids.len() != baseline_analyses.len()
                || project_ids.len() != candidate_analyses.len()
            {
                bail!(
                    "policy rollout requires one board, baseline, and candidate analysis per project ID"
                );
            }
            if project_ids.len() > 1_000 {
                bail!("policy rollout accepts at most 1000 projects");
            }
            let policy = load_policy_pack(&policy_pack)?.0;
            let recommendation_source = fs::read_to_string(&recommendation)
                .with_context(|| format!("reading {}", recommendation.display()))?;
            let recommendation = parse_policy_recommendation_report(&recommendation_source)
                .map_err(anyhow::Error::msg)?;
            struct OwnedAnalysis {
                run_path: String,
                run: Vec<u8>,
                checks_path: String,
                checks: Vec<u8>,
                quality_path: String,
                quality: Vec<u8>,
            }
            fn read_analysis(directory: &Path) -> Result<OwnedAnalysis> {
                let run_path = directory.join("run.json");
                let checks_path = directory.join("checks.json");
                let quality_path = directory.join("quality.json");
                Ok(OwnedAnalysis {
                    run: fs::read(&run_path)
                        .with_context(|| format!("reading {}", run_path.display()))?,
                    checks: fs::read(&checks_path)
                        .with_context(|| format!("reading {}", checks_path.display()))?,
                    quality: fs::read(&quality_path)
                        .with_context(|| format!("reading {}", quality_path.display()))?,
                    run_path: run_path.display().to_string(),
                    checks_path: checks_path.display().to_string(),
                    quality_path: quality_path.display().to_string(),
                })
            }
            let analyses = boards
                .iter()
                .zip(&baseline_analyses)
                .zip(&candidate_analyses)
                .map(|((board, baseline), candidate)| {
                    Ok((
                        board.display().to_string(),
                        fs::read(board).with_context(|| format!("reading {}", board.display()))?,
                        read_analysis(baseline)?,
                        read_analysis(candidate)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let inputs = project_ids
                .iter()
                .zip(&analyses)
                .map(
                    |(project_id, (board_path, board, baseline, candidate))| RolloutProjectInput {
                        project_id,
                        board_path,
                        board,
                        baseline: RolloutAnalysisInput {
                            run_path: &baseline.run_path,
                            run: &baseline.run,
                            checks_path: &baseline.checks_path,
                            checks: &baseline.checks,
                            quality_path: &baseline.quality_path,
                            quality: &baseline.quality,
                        },
                        candidate: RolloutAnalysisInput {
                            run_path: &candidate.run_path,
                            run: &candidate.run,
                            checks_path: &candidate.checks_path,
                            checks: &candidate.checks,
                            quality_path: &candidate.quality_path,
                            quality: &candidate.quality,
                        },
                    },
                )
                .collect::<Vec<_>>();
            let report = simulate_policy_rollout(&policy, &recommendation, &generated_on, &inputs)
                .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            let summary = render_policy_rollout_summary(&report);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy rollout simulation: {} compatible, {} affected; human approval required",
                report.compatible_projects, report.affected_projects
            );
        }
        Command::SignRolloutApproval {
            rollout,
            canary_projects,
            valid_from_unix,
            expires_at_unix,
            private_key,
            signer_id,
            decision,
            reason,
            ticket,
            output,
        } => {
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let secret = read_hex_key(&private_key, "rollout approval private key")?;
            let approval = sign_rollout_approval(
                &rollout,
                decision.into(),
                &canary_projects,
                valid_from_unix,
                expires_at_unix,
                &reason,
                &ticket,
                &signer_id,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&approval)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "signed {:?} canary decision for {} as {}",
                approval.decision, approval.rollout_sha256, approval.signer_id
            );
        }
        Command::VerifyRolloutApprovals {
            rollout,
            policy_pack,
            approvals,
            evaluated_at_unix,
            minimum_approvals,
            output,
            summary_output,
            require_authorized,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "canary rollout authorization",
            )?;
            if approvals.len() > 100 {
                bail!("canary rollout verification accepts at most 100 approvals");
            }
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let policy = load_policy_pack(&policy_pack)?.0;
            let approvals = approvals
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_rollout_approval(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let authorization = verify_rollout_approvals(
                &rollout,
                &policy,
                &approvals,
                evaluated_at_unix,
                minimum_approvals,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&authorization)? + "\n";
            let summary = render_canary_authorization_summary(&authorization);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "canary rollout: {}/{} approval(s), {} rejection(s): {}",
                authorization.approvals,
                authorization.policy.minimum_approvals,
                authorization.rejections,
                authorization.status
            );
            if require_authorized && !authorization.canary_authorized {
                bail!("canary rollout did not receive bounded dual-control authorization");
            }
        }
        Command::RecordCanaryMonitoring {
            rollout,
            authorization,
            project_ids,
            boards,
            baseline_analyses,
            observed_analyses,
            observed_at_unix,
            output,
            summary_output,
            require_passed,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "canary monitoring",
            )?;
            if project_ids.len() != boards.len()
                || project_ids.len() != baseline_analyses.len()
                || project_ids.len() != observed_analyses.len()
            {
                bail!(
                    "canary monitoring requires one board, baseline, and observed analysis per project ID"
                );
            }
            if project_ids.len() > 100 {
                bail!("canary monitoring accepts at most 100 projects");
            }
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let authorization_source = fs::read_to_string(&authorization)
                .with_context(|| format!("reading {}", authorization.display()))?;
            let authorization =
                parse_canary_authorization(&authorization_source).map_err(anyhow::Error::msg)?;
            struct OwnedAnalysis {
                run_path: String,
                run: Vec<u8>,
                checks_path: String,
                checks: Vec<u8>,
                quality_path: String,
                quality: Vec<u8>,
            }
            fn read_analysis(directory: &Path) -> Result<OwnedAnalysis> {
                let run_path = directory.join("run.json");
                let checks_path = directory.join("checks.json");
                let quality_path = directory.join("quality.json");
                Ok(OwnedAnalysis {
                    run: fs::read(&run_path)
                        .with_context(|| format!("reading {}", run_path.display()))?,
                    checks: fs::read(&checks_path)
                        .with_context(|| format!("reading {}", checks_path.display()))?,
                    quality: fs::read(&quality_path)
                        .with_context(|| format!("reading {}", quality_path.display()))?,
                    run_path: run_path.display().to_string(),
                    checks_path: checks_path.display().to_string(),
                    quality_path: quality_path.display().to_string(),
                })
            }
            let analyses = boards
                .iter()
                .zip(&baseline_analyses)
                .zip(&observed_analyses)
                .map(|((board, baseline), observed)| {
                    Ok((
                        board.display().to_string(),
                        fs::read(board).with_context(|| format!("reading {}", board.display()))?,
                        read_analysis(baseline)?,
                        read_analysis(observed)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let inputs = project_ids
                .iter()
                .zip(&analyses)
                .map(|(project_id, (board_path, board, baseline, observed))| {
                    CanaryMonitoringInput {
                        project_id,
                        board_path,
                        board,
                        baseline: RolloutAnalysisInput {
                            run_path: &baseline.run_path,
                            run: &baseline.run,
                            checks_path: &baseline.checks_path,
                            checks: &baseline.checks,
                            quality_path: &baseline.quality_path,
                            quality: &baseline.quality,
                        },
                        observed: RolloutAnalysisInput {
                            run_path: &observed.run_path,
                            run: &observed.run,
                            checks_path: &observed.checks_path,
                            checks: &observed.checks,
                            quality_path: &observed.quality_path,
                            quality: &observed.quality,
                        },
                    }
                })
                .collect::<Vec<_>>();
            let report =
                record_canary_monitoring(&rollout, &authorization, observed_at_unix, &inputs)
                    .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            let summary = render_canary_monitoring_summary(&report);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "canary monitoring: {} passed, {} failed: {}",
                report.passed_projects, report.failed_projects, report.status
            );
            if require_passed && !report.promotion_eligible {
                bail!("canary monitoring requires rollback");
            }
        }
        Command::SignCanaryCompletion {
            rollout,
            monitoring,
            authorization,
            decision,
            decided_at_unix,
            private_key,
            signer_id,
            reason,
            ticket,
            output,
        } => {
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let monitoring_source = fs::read_to_string(&monitoring)
                .with_context(|| format!("reading {}", monitoring.display()))?;
            let monitoring =
                parse_canary_monitoring_report(&monitoring_source).map_err(anyhow::Error::msg)?;
            let authorization_source = fs::read_to_string(&authorization)
                .with_context(|| format!("reading {}", authorization.display()))?;
            let authorization =
                parse_canary_authorization(&authorization_source).map_err(anyhow::Error::msg)?;
            let secret = read_hex_key(&private_key, "canary completion private key")?;
            let signed = sign_canary_completion(
                &rollout,
                &monitoring,
                &authorization,
                decision.into(),
                decided_at_unix,
                &reason,
                &ticket,
                &signer_id,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&signed)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "signed {:?} canary completion decision as {}",
                signed.decision, signed.signer_id
            );
        }
        Command::VerifyCanaryCompletion {
            rollout,
            monitoring,
            authorization,
            policy_pack,
            decisions,
            minimum_decisions,
            output,
            summary_output,
            require_finalized,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "canary completion",
            )?;
            if decisions.len() > 100 {
                bail!("canary completion accepts at most 100 decisions");
            }
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let monitoring_source = fs::read_to_string(&monitoring)
                .with_context(|| format!("reading {}", monitoring.display()))?;
            let monitoring =
                parse_canary_monitoring_report(&monitoring_source).map_err(anyhow::Error::msg)?;
            let authorization_source = fs::read_to_string(&authorization)
                .with_context(|| format!("reading {}", authorization.display()))?;
            let authorization =
                parse_canary_authorization(&authorization_source).map_err(anyhow::Error::msg)?;
            let policy = load_policy_pack(&policy_pack)?.0;
            let decisions = decisions
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_canary_decision(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let report = verify_canary_completion(
                &rollout,
                &monitoring,
                &authorization,
                &policy,
                &decisions,
                minimum_decisions,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            let summary = render_canary_completion_summary(&report);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "canary completion: {} promotion, {} rollback decision(s): {}",
                report.promotions, report.rollbacks, report.status
            );
            if require_finalized && !report.finalized {
                bail!("canary completion did not receive a valid unanimous quorum");
            }
        }
        Command::AdvancePolicyDeployment {
            rollout,
            monitoring,
            authorization,
            policy_pack,
            candidate_policy_pack,
            source_policy_trust_state,
            candidate_policy_trust_state,
            decisions,
            minimum_decisions,
            baseline_state,
            suspension_states,
            remediation_states,
            policy_lifecycle_ledgers,
            recorded_at_unix,
            output,
            summary_output,
            require_promotion,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy deployment",
            )?;
            if decisions.len() > 100 {
                bail!("policy deployment accepts at most 100 completion decisions");
            }
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let monitoring_source = fs::read_to_string(&monitoring)
                .with_context(|| format!("reading {}", monitoring.display()))?;
            let monitoring =
                parse_canary_monitoring_report(&monitoring_source).map_err(anyhow::Error::msg)?;
            let authorization_source = fs::read_to_string(&authorization)
                .with_context(|| format!("reading {}", authorization.display()))?;
            let authorization =
                parse_canary_authorization(&authorization_source).map_err(anyhow::Error::msg)?;
            let policy = load_policy_pack(&policy_pack)?.0;
            let candidate_policy = load_policy_pack(&candidate_policy_pack)?.0;
            let mut suspension_states = suspension_states
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_suspension_state(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let mut remediation_states = remediation_states
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_remediation_state(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            for path in &policy_lifecycle_ledgers {
                let source = fs::read_to_string(path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let ledger = parse_policy_lifecycle_ledger(&source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("parsing {}", path.display()))?;
                let (mut retained_suspensions, mut retained_remediations) =
                    lifecycle_evidence(&ledger).map_err(anyhow::Error::msg)?;
                suspension_states.append(&mut retained_suspensions);
                remediation_states.append(&mut retained_remediations);
            }
            enforce_policy_suspensions(&candidate_policy, &suspension_states, &remediation_states)
                .map_err(anyhow::Error::msg)?;
            let source_trust_state = load_policy_trust_state(&source_policy_trust_state)?;
            let candidate_trust_state = load_policy_trust_state(&candidate_policy_trust_state)?;
            let decisions = decisions
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_canary_decision(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let baseline = baseline_state
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_deployment_state(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .transpose()?;
            let state = advance_policy_deployment(
                &rollout,
                &monitoring,
                &authorization,
                &policy,
                &candidate_policy,
                &source_trust_state,
                &candidate_trust_state,
                &decisions,
                minimum_decisions,
                baseline.as_ref(),
                recorded_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&state)? + "\n";
            let summary = render_policy_deployment_summary(&state);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy deployment generation {}: {:?}, active revision {}",
                state.generation, state.status, state.active_revision
            );
            if require_promotion && !state.deployment_applied {
                bail!("policy deployment retained rollback without promoting the candidate");
            }
        }
        Command::VerifyPolicyDeployment {
            deployment,
            rollout,
            candidate_policy_pack,
            project_ids,
            boards,
            expected_analyses,
            observed_analyses,
            verified_at_unix,
            output,
            summary_output,
            require_passed,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "post-deployment verification",
            )?;
            if project_ids.len() != boards.len()
                || project_ids.len() != expected_analyses.len()
                || project_ids.len() != observed_analyses.len()
            {
                bail!(
                    "post-deployment verification requires one board, expected, and observed analysis per project ID"
                );
            }
            if project_ids.len() > 1_000 {
                bail!("post-deployment verification accepts at most 1000 projects");
            }
            let deployment_source = fs::read_to_string(&deployment)
                .with_context(|| format!("reading {}", deployment.display()))?;
            let deployment =
                parse_policy_deployment_state(&deployment_source).map_err(anyhow::Error::msg)?;
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let candidate_policy_pack_bytes = fs::read(&candidate_policy_pack)
                .with_context(|| format!("reading {}", candidate_policy_pack.display()))?;
            let candidate_policy_source = std::str::from_utf8(&candidate_policy_pack_bytes)
                .with_context(|| {
                    format!(
                        "{} is not UTF-8 policy JSON",
                        candidate_policy_pack.display()
                    )
                })?;
            let candidate_policy =
                parse_policy_pack(candidate_policy_source).map_err(anyhow::Error::msg)?;
            struct OwnedAnalysis {
                run_path: String,
                run: Vec<u8>,
                checks_path: String,
                checks: Vec<u8>,
                quality_path: String,
                quality: Vec<u8>,
            }
            fn read_analysis(directory: &Path) -> Result<OwnedAnalysis> {
                let run_path = directory.join("run.json");
                let checks_path = directory.join("checks.json");
                let quality_path = directory.join("quality.json");
                Ok(OwnedAnalysis {
                    run: fs::read(&run_path)
                        .with_context(|| format!("reading {}", run_path.display()))?,
                    checks: fs::read(&checks_path)
                        .with_context(|| format!("reading {}", checks_path.display()))?,
                    quality: fs::read(&quality_path)
                        .with_context(|| format!("reading {}", quality_path.display()))?,
                    run_path: run_path.display().to_string(),
                    checks_path: checks_path.display().to_string(),
                    quality_path: quality_path.display().to_string(),
                })
            }
            let analyses = boards
                .iter()
                .zip(&expected_analyses)
                .zip(&observed_analyses)
                .map(|((board, expected), observed)| {
                    Ok((
                        board.display().to_string(),
                        fs::read(board).with_context(|| format!("reading {}", board.display()))?,
                        read_analysis(expected)?,
                        read_analysis(observed)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let inputs = project_ids
                .iter()
                .zip(&analyses)
                .map(|(project_id, (board_path, board, expected, observed))| {
                    CanaryMonitoringInput {
                        project_id,
                        board_path,
                        board,
                        baseline: RolloutAnalysisInput {
                            run_path: &expected.run_path,
                            run: &expected.run,
                            checks_path: &expected.checks_path,
                            checks: &expected.checks,
                            quality_path: &expected.quality_path,
                            quality: &expected.quality,
                        },
                        observed: RolloutAnalysisInput {
                            run_path: &observed.run_path,
                            run: &observed.run,
                            checks_path: &observed.checks_path,
                            checks: &observed.checks,
                            quality_path: &observed.quality_path,
                            quality: &observed.quality,
                        },
                    }
                })
                .collect::<Vec<_>>();
            let report = verify_policy_deployment(
                &deployment,
                &rollout,
                &candidate_policy,
                &candidate_policy_pack_bytes,
                verified_at_unix,
                &inputs,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            let summary = render_policy_deployment_verification_summary(&report);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "post-deployment verification: {} passed, {} failed: {}",
                report.passed_projects, report.failed_projects, report.status
            );
            if require_passed && !report.deployment_verified {
                bail!("post-deployment verification requires dual-control rollback");
            }
        }
        Command::SignPolicyDeploymentRollback {
            deployment,
            verification,
            approved_at_unix,
            private_key,
            signer_id,
            reason,
            ticket,
            output,
        } => {
            let deployment_source = fs::read_to_string(&deployment)
                .with_context(|| format!("reading {}", deployment.display()))?;
            let deployment =
                parse_policy_deployment_state(&deployment_source).map_err(anyhow::Error::msg)?;
            let verification_source = fs::read_to_string(&verification)
                .with_context(|| format!("reading {}", verification.display()))?;
            let verification = parse_policy_deployment_verification(&verification_source)
                .map_err(anyhow::Error::msg)?;
            let secret = read_hex_key(&private_key, "deployment rollback private key")?;
            let approval = sign_policy_deployment_rollback(
                &deployment,
                &verification,
                approved_at_unix,
                &reason,
                &ticket,
                &signer_id,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&approval)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!("signed policy deployment rollback as {signer_id}");
        }
        Command::ApplyPolicyDeploymentRollback {
            deployment,
            verification,
            active_policy_pack,
            approvals,
            minimum_approvals,
            recorded_at_unix,
            output,
            summary_output,
            require_applied,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy deployment rollback",
            )?;
            if approvals.len() > 100 {
                bail!("policy deployment rollback accepts at most 100 approvals");
            }
            let deployment_source = fs::read_to_string(&deployment)
                .with_context(|| format!("reading {}", deployment.display()))?;
            let deployment =
                parse_policy_deployment_state(&deployment_source).map_err(anyhow::Error::msg)?;
            let verification_source = fs::read_to_string(&verification)
                .with_context(|| format!("reading {}", verification.display()))?;
            let verification = parse_policy_deployment_verification(&verification_source)
                .map_err(anyhow::Error::msg)?;
            let active_policy = load_policy_pack(&active_policy_pack)?.0;
            let approvals = approvals
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_policy_deployment_rollback(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let state = apply_policy_deployment_rollback(
                &deployment,
                &verification,
                &active_policy,
                &approvals,
                minimum_approvals,
                recorded_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&state)? + "\n";
            let summary = render_policy_deployment_rollback_summary(&state);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy deployment rollback: revision {} restored from failed revision {}",
                state.active_revision, state.failed_revision
            );
            if require_applied && !state.rollback_applied {
                bail!("policy deployment rollback was not applied");
            }
        }
        Command::VerifyPolicyRollbackRecovery {
            rollback,
            rollout,
            deployment,
            failed_verification,
            previous_deployment,
            baseline_verification,
            restored_policy_pack,
            project_ids,
            boards,
            expected_analyses,
            observed_analyses,
            verified_at_unix,
            output,
            summary_output,
            require_passed,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy rollback recovery",
            )?;
            if project_ids.len() != boards.len()
                || project_ids.len() != expected_analyses.len()
                || project_ids.len() != observed_analyses.len()
            {
                bail!(
                    "policy rollback recovery requires one board, expected, and observed analysis per project ID"
                );
            }
            if project_ids.len() > 1_000 {
                bail!("policy rollback recovery accepts at most 1000 projects");
            }
            let rollback_source = fs::read_to_string(&rollback)
                .with_context(|| format!("reading {}", rollback.display()))?;
            let rollback = parse_policy_deployment_rollback_state(&rollback_source)
                .map_err(anyhow::Error::msg)?;
            let deployment_source = fs::read_to_string(&deployment)
                .with_context(|| format!("reading {}", deployment.display()))?;
            let deployment =
                parse_policy_deployment_state(&deployment_source).map_err(anyhow::Error::msg)?;
            let failed_verification_source = fs::read_to_string(&failed_verification)
                .with_context(|| format!("reading {}", failed_verification.display()))?;
            let failed_verification =
                parse_policy_deployment_verification(&failed_verification_source)
                    .map_err(anyhow::Error::msg)?;
            let previous_deployment_source = fs::read_to_string(&previous_deployment)
                .with_context(|| format!("reading {}", previous_deployment.display()))?;
            let previous_deployment = parse_policy_deployment_state(&previous_deployment_source)
                .map_err(anyhow::Error::msg)?;
            let baseline_verification_source = fs::read_to_string(&baseline_verification)
                .with_context(|| format!("reading {}", baseline_verification.display()))?;
            let baseline_verification =
                parse_policy_deployment_verification(&baseline_verification_source)
                    .map_err(anyhow::Error::msg)?;
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let restored_policy_pack_bytes = fs::read(&restored_policy_pack)
                .with_context(|| format!("reading {}", restored_policy_pack.display()))?;
            let restored_policy_source = std::str::from_utf8(&restored_policy_pack_bytes)
                .with_context(|| {
                    format!(
                        "{} is not UTF-8 policy JSON",
                        restored_policy_pack.display()
                    )
                })?;
            let restored_policy =
                parse_policy_pack(restored_policy_source).map_err(anyhow::Error::msg)?;
            struct OwnedAnalysis {
                run_path: String,
                run: Vec<u8>,
                checks_path: String,
                checks: Vec<u8>,
                quality_path: String,
                quality: Vec<u8>,
            }
            fn read_analysis(directory: &Path) -> Result<OwnedAnalysis> {
                let run_path = directory.join("run.json");
                let checks_path = directory.join("checks.json");
                let quality_path = directory.join("quality.json");
                Ok(OwnedAnalysis {
                    run: fs::read(&run_path)
                        .with_context(|| format!("reading {}", run_path.display()))?,
                    checks: fs::read(&checks_path)
                        .with_context(|| format!("reading {}", checks_path.display()))?,
                    quality: fs::read(&quality_path)
                        .with_context(|| format!("reading {}", quality_path.display()))?,
                    run_path: run_path.display().to_string(),
                    checks_path: checks_path.display().to_string(),
                    quality_path: quality_path.display().to_string(),
                })
            }
            let analyses = boards
                .iter()
                .zip(&expected_analyses)
                .zip(&observed_analyses)
                .map(|((board, expected), observed)| {
                    Ok((
                        board.display().to_string(),
                        fs::read(board).with_context(|| format!("reading {}", board.display()))?,
                        read_analysis(expected)?,
                        read_analysis(observed)?,
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            let inputs = project_ids
                .iter()
                .zip(&analyses)
                .map(|(project_id, (board_path, board, expected, observed))| {
                    CanaryMonitoringInput {
                        project_id,
                        board_path,
                        board,
                        baseline: RolloutAnalysisInput {
                            run_path: &expected.run_path,
                            run: &expected.run,
                            checks_path: &expected.checks_path,
                            checks: &expected.checks,
                            quality_path: &expected.quality_path,
                            quality: &expected.quality,
                        },
                        observed: RolloutAnalysisInput {
                            run_path: &observed.run_path,
                            run: &observed.run,
                            checks_path: &observed.checks_path,
                            checks: &observed.checks,
                            quality_path: &observed.quality_path,
                            quality: &observed.quality,
                        },
                    }
                })
                .collect::<Vec<_>>();
            let report = verify_policy_rollback_recovery(
                &PolicyRollbackRecoveryEvidence {
                    rollback: &rollback,
                    failed_deployment: &deployment,
                    failed_verification: &failed_verification,
                    previous_deployment: &previous_deployment,
                    baseline_verification: &baseline_verification,
                    rollout: &rollout,
                },
                &restored_policy,
                &restored_policy_pack_bytes,
                verified_at_unix,
                &inputs,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            let summary = render_policy_rollback_recovery_summary(&report);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy rollback recovery: {} passed, {} failed: {}",
                report.passed_projects, report.failed_projects, report.status
            );
            if require_passed && !report.recovery_verified {
                bail!("policy rollback recovery is incomplete or regressed");
            }
        }
        Command::SignRollbackIncidentAcknowledgment {
            rollback,
            recovery,
            acknowledged_at_unix,
            private_key,
            operator_id,
            reason,
            ticket,
            output,
        } => {
            let rollback_source = fs::read_to_string(&rollback)
                .with_context(|| format!("reading {}", rollback.display()))?;
            let rollback = parse_policy_deployment_rollback_state(&rollback_source)
                .map_err(anyhow::Error::msg)?;
            let recovery_source = fs::read_to_string(&recovery)
                .with_context(|| format!("reading {}", recovery.display()))?;
            let recovery =
                parse_policy_rollback_recovery(&recovery_source).map_err(anyhow::Error::msg)?;
            let secret = read_hex_key(&private_key, "rollback incident operator private key")?;
            let acknowledgment = sign_rollback_incident_acknowledgment(
                &rollback,
                &recovery,
                acknowledged_at_unix,
                &operator_id,
                &reason,
                &ticket,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&acknowledgment)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!("signed rollback incident acknowledgment as {operator_id}");
        }
        Command::CloseRollbackIncident {
            rollback,
            recovery,
            restored_policy_pack,
            acknowledgment,
            closed_at_unix,
            output,
            summary_output,
            require_closed,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "rollback incident closure",
            )?;
            let rollback_source = fs::read_to_string(&rollback)
                .with_context(|| format!("reading {}", rollback.display()))?;
            let rollback = parse_policy_deployment_rollback_state(&rollback_source)
                .map_err(anyhow::Error::msg)?;
            let recovery_source = fs::read_to_string(&recovery)
                .with_context(|| format!("reading {}", recovery.display()))?;
            let recovery =
                parse_policy_rollback_recovery(&recovery_source).map_err(anyhow::Error::msg)?;
            let restored_policy = load_policy_pack(&restored_policy_pack)?.0;
            let acknowledgment_source = fs::read_to_string(&acknowledgment)
                .with_context(|| format!("reading {}", acknowledgment.display()))?;
            let acknowledgment =
                parse_signed_rollback_incident_acknowledgment(&acknowledgment_source)
                    .map_err(anyhow::Error::msg)?;
            let state = close_rollback_incident(
                &rollback,
                &recovery,
                &restored_policy,
                &acknowledgment,
                closed_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&state)? + "\n";
            let summary = render_rollback_incident_closure_summary(&state);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "rollback incident closed by {} for {}",
                state.operator_id, state.ticket
            );
            if require_closed && !state.incident_closed {
                bail!("rollback incident was not closed");
            }
        }
        Command::AppendPolicyIncidentLedger {
            rollback,
            failed_verification,
            recovery,
            closure,
            baseline_ledger,
            suspension_threshold,
            output,
            summary_output,
            require_no_suspension_review,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy incident ledger",
            )?;
            let rollback_source = fs::read_to_string(&rollback)
                .with_context(|| format!("reading {}", rollback.display()))?;
            let rollback = parse_policy_deployment_rollback_state(&rollback_source)
                .map_err(anyhow::Error::msg)?;
            let failed_verification_source = fs::read_to_string(&failed_verification)
                .with_context(|| format!("reading {}", failed_verification.display()))?;
            let failed_verification =
                parse_policy_deployment_verification(&failed_verification_source)
                    .map_err(anyhow::Error::msg)?;
            let recovery_source = fs::read_to_string(&recovery)
                .with_context(|| format!("reading {}", recovery.display()))?;
            let recovery =
                parse_policy_rollback_recovery(&recovery_source).map_err(anyhow::Error::msg)?;
            let closure_source = fs::read_to_string(&closure)
                .with_context(|| format!("reading {}", closure.display()))?;
            let closure =
                parse_rollback_incident_closure(&closure_source).map_err(anyhow::Error::msg)?;
            let baseline = baseline_ledger
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_incident_ledger(&source).map_err(anyhow::Error::msg)
                })
                .transpose()?;
            let ledger = append_policy_incident(
                baseline.as_ref(),
                &rollback,
                &failed_verification,
                &recovery,
                &closure,
                suspension_threshold,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&ledger)? + "\n";
            let summary = render_policy_incident_ledger_summary(&ledger);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy incident ledger: {} incident(s), suspension review {}",
                ledger.entry_count, ledger.requires_human_suspension_review
            );
            if require_no_suspension_review && ledger.requires_human_suspension_review {
                bail!("policy incident ledger requires human suspension review");
            }
        }
        Command::SignPolicySuspensionDecision {
            ledger,
            failed_revision,
            failed_policy_pack_sha256,
            decision,
            decided_at_unix,
            private_key,
            signer_id,
            reason,
            ticket,
            output,
        } => {
            let ledger_source = fs::read_to_string(&ledger)
                .with_context(|| format!("reading {}", ledger.display()))?;
            let ledger =
                parse_policy_incident_ledger(&ledger_source).map_err(anyhow::Error::msg)?;
            let secret = read_secret_key(&private_key)?;
            let signed = sign_policy_suspension_decision(
                &ledger,
                failed_revision,
                &failed_policy_pack_sha256,
                decision.into(),
                decided_at_unix,
                &reason,
                &ticket,
                &signer_id,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&signed)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!("signed policy suspension decision as {signer_id}");
        }
        Command::ApplyPolicySuspensionDecision {
            ledger,
            policy_pack,
            failed_revision,
            failed_policy_pack_sha256,
            decisions,
            minimum_decisions,
            recorded_at_unix,
            output,
            summary_output,
            require_suspended,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy suspension state",
            )?;
            if decisions.len() > 100 {
                bail!("policy suspension accepts at most 100 decisions");
            }
            let ledger_source = fs::read_to_string(&ledger)
                .with_context(|| format!("reading {}", ledger.display()))?;
            let ledger =
                parse_policy_incident_ledger(&ledger_source).map_err(anyhow::Error::msg)?;
            let policy = load_policy_pack(&policy_pack)?.0;
            let decisions = decisions
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_policy_suspension_decision(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let state = apply_policy_suspension_decision(
                &ledger,
                &policy,
                failed_revision,
                &failed_policy_pack_sha256,
                &decisions,
                minimum_decisions,
                recorded_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&state)? + "\n";
            let summary = render_policy_suspension_summary(&state);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!("policy suspension decision retained: {}", state.status);
            if require_suspended && !state.policy_suspended {
                bail!("policy suspension quorum chose to continue under review");
            }
        }
        Command::SignPolicyRemediationApproval {
            suspension,
            candidate_policy_pack,
            candidate_policy_trust_state,
            rollout,
            monitoring,
            approved_at_unix,
            private_key,
            signer_id,
            reason,
            ticket,
            output,
        } => {
            let suspension_source = fs::read_to_string(&suspension)
                .with_context(|| format!("reading {}", suspension.display()))?;
            let suspension =
                parse_policy_suspension_state(&suspension_source).map_err(anyhow::Error::msg)?;
            let candidate = load_policy_pack(&candidate_policy_pack)?.0;
            let candidate_trust_state = load_policy_trust_state(&candidate_policy_trust_state)?;
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let monitoring_source = fs::read_to_string(&monitoring)
                .with_context(|| format!("reading {}", monitoring.display()))?;
            let monitoring =
                parse_canary_monitoring_report(&monitoring_source).map_err(anyhow::Error::msg)?;
            let secret = read_secret_key(&private_key)?;
            let approval = sign_policy_remediation_approval(
                &suspension,
                &candidate,
                &candidate_trust_state,
                &rollout,
                &monitoring,
                approved_at_unix,
                &reason,
                &ticket,
                &signer_id,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&approval)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!("signed policy remediation approval as {signer_id}");
        }
        Command::ApplyPolicyRemediation {
            suspension,
            policy_pack,
            candidate_policy_pack,
            candidate_policy_trust_state,
            rollout,
            monitoring,
            approvals,
            minimum_approvals,
            recorded_at_unix,
            output,
            summary_output,
            require_verified,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy remediation",
            )?;
            if approvals.len() > 100 {
                bail!("policy remediation accepts at most 100 approvals");
            }
            let suspension_source = fs::read_to_string(&suspension)
                .with_context(|| format!("reading {}", suspension.display()))?;
            let suspension =
                parse_policy_suspension_state(&suspension_source).map_err(anyhow::Error::msg)?;
            let policy = load_policy_pack(&policy_pack)?.0;
            let candidate = load_policy_pack(&candidate_policy_pack)?.0;
            let candidate_trust_state = load_policy_trust_state(&candidate_policy_trust_state)?;
            let rollout_source = fs::read_to_string(&rollout)
                .with_context(|| format!("reading {}", rollout.display()))?;
            let rollout =
                parse_policy_rollout_report(&rollout_source).map_err(anyhow::Error::msg)?;
            let monitoring_source = fs::read_to_string(&monitoring)
                .with_context(|| format!("reading {}", monitoring.display()))?;
            let monitoring =
                parse_canary_monitoring_report(&monitoring_source).map_err(anyhow::Error::msg)?;
            let approvals = approvals
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_policy_remediation_approval(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let state = apply_policy_remediation(
                &suspension,
                &policy,
                &candidate,
                &candidate_trust_state,
                &rollout,
                &monitoring,
                &approvals,
                minimum_approvals,
                recorded_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&state)? + "\n";
            let summary = render_policy_remediation_summary(&state);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy remediation retained for revision {}",
                state.remediation_revision
            );
            if require_verified && !state.suspension_lifted_for_remediation {
                bail!("policy remediation was not independently verified");
            }
        }
        Command::AppendPolicyLifecycleEvent {
            baseline_ledger,
            suspension,
            remediation,
            output,
            summary_output,
            require_no_pending_suspensions,
        } => {
            require_distinct_outputs(
                [Some(output.as_path()), summary_output.as_deref()],
                "policy lifecycle",
            )?;
            let baseline = baseline_ledger
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_lifecycle_ledger(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .transpose()?;
            let suspension = suspension
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_suspension_state(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .transpose()?;
            let remediation = remediation
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_remediation_state(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .transpose()?;
            let ledger = append_policy_lifecycle_event(
                baseline.as_ref(),
                suspension.as_ref(),
                remediation.as_ref(),
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&ledger)? + "\n";
            let summary = render_policy_lifecycle_summary(&ledger);
            let mut files = vec![(output.as_path(), document.as_str())];
            if let Some(path) = summary_output.as_deref() {
                files.push((path, summary.as_str()));
            }
            write_new_file_set(&files)?;
            eprintln!(
                "policy lifecycle generation {} retained: {} pending suspension(s)",
                ledger.generation, ledger.awaiting_remediation
            );
            if require_no_pending_suspensions && ledger.awaiting_remediation != 0 {
                bail!(
                    "policy lifecycle has {} suspension(s) awaiting remediation",
                    ledger.awaiting_remediation
                );
            }
        }
        Command::SnapshotPolicyLifecycle {
            ledger,
            generation,
            output,
        } => {
            let source = fs::read_to_string(&ledger)
                .with_context(|| format!("reading {}", ledger.display()))?;
            let ledger = parse_policy_lifecycle_ledger(&source).map_err(anyhow::Error::msg)?;
            let snapshot =
                snapshot_policy_lifecycle(&ledger, generation).map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&snapshot)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "policy lifecycle snapshot generation {}: {} pending suspension(s)",
                snapshot.generation, snapshot.awaiting_remediation
            );
        }
        Command::SignPolicyLifecycleCheckpoint {
            ledger,
            issued_at_unix,
            private_key,
            signer_id,
            output,
        } => {
            let source = fs::read_to_string(&ledger)
                .with_context(|| format!("reading {}", ledger.display()))?;
            let ledger = parse_policy_lifecycle_ledger(&source).map_err(anyhow::Error::msg)?;
            let secret = read_hex_key(
                &private_key,
                "policy lifecycle checkpoint signing private key",
            )?;
            let checkpoint =
                sign_policy_lifecycle_checkpoint(&ledger, issued_at_unix, &signer_id, &secret)
                    .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&checkpoint)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "signed policy lifecycle checkpoint generation {} as {}",
                checkpoint.generation, checkpoint.signer_id
            );
        }
        Command::VerifyPolicyLifecycleCheckpoint {
            ledger,
            checkpoint,
            public_key,
            baseline_state,
            key_rotation,
            accepted_at_unix,
            output,
            require_accepted,
        } => {
            let ledger_source = fs::read_to_string(&ledger)
                .with_context(|| format!("reading {}", ledger.display()))?;
            let ledger =
                parse_policy_lifecycle_ledger(&ledger_source).map_err(anyhow::Error::msg)?;
            let checkpoint_source = fs::read_to_string(&checkpoint)
                .with_context(|| format!("reading {}", checkpoint.display()))?;
            let checkpoint = parse_signed_policy_lifecycle_checkpoint(&checkpoint_source)
                .map_err(anyhow::Error::msg)?;
            let public_key = read_hex_key(
                &public_key,
                "trusted policy lifecycle checkpoint public key",
            )?;
            let baseline = baseline_state
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_policy_lifecycle_trust_state(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .transpose()?;
            let key_rotation = key_rotation
                .as_ref()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_policy_lifecycle_key_rotation(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .transpose()?;
            let state = verify_policy_lifecycle_checkpoint(
                &ledger,
                &checkpoint,
                &public_key,
                baseline.as_ref(),
                key_rotation.as_ref(),
                accepted_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&state)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "accepted policy lifecycle checkpoint generation {} signed by {}",
                state.accepted_generation, state.signer_id
            );
            if require_accepted && state.status != "checkpoint_accepted" {
                bail!("policy lifecycle checkpoint was not accepted");
            }
        }
        Command::SignPolicyLifecycleKeyRotation {
            baseline_state,
            old_private_key,
            new_private_key,
            rotated_at_unix,
            output,
        } => {
            let source = fs::read_to_string(&baseline_state)
                .with_context(|| format!("reading {}", baseline_state.display()))?;
            let baseline =
                parse_policy_lifecycle_trust_state(&source).map_err(anyhow::Error::msg)?;
            let old_key =
                read_hex_key(&old_private_key, "old policy lifecycle signing private key")?;
            let new_key =
                read_hex_key(&new_private_key, "new policy lifecycle signing private key")?;
            let rotation =
                sign_policy_lifecycle_key_rotation(&baseline, &old_key, &new_key, rotated_at_unix)
                    .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&rotation)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "signed policy lifecycle key rotation generation {} -> {}",
                rotation.from_key_generation, rotation.to_key_generation
            );
        }
        Command::WitnessPolicyLifecycleCheckpoint {
            trust_state,
            private_key,
            witness_id,
            observed_at_unix,
            output,
        } => {
            let source = fs::read_to_string(&trust_state)
                .with_context(|| format!("reading {}", trust_state.display()))?;
            let state = parse_policy_lifecycle_trust_state(&source).map_err(anyhow::Error::msg)?;
            let secret =
                read_hex_key(&private_key, "policy lifecycle witness signing private key")?;
            let witness = sign_policy_lifecycle_checkpoint_witness(
                &state,
                &witness_id,
                observed_at_unix,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&witness)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "witnessed policy lifecycle checkpoint generation {} as {}",
                witness.generation, witness.witness_id
            );
        }
        Command::VerifyPolicyLifecycleCheckpointWitnesses {
            trust_state,
            witnesses,
            public_keys,
            minimum_witnesses,
            evaluated_at_unix,
            output,
            require_quorum,
        } => {
            if witnesses.len() != public_keys.len() {
                bail!("policy lifecycle witnesses and public keys must be paired");
            }
            let source = fs::read_to_string(&trust_state)
                .with_context(|| format!("reading {}", trust_state.display()))?;
            let state = parse_policy_lifecycle_trust_state(&source).map_err(anyhow::Error::msg)?;
            let witnesses = witnesses
                .iter()
                .map(|path| {
                    let source = fs::read_to_string(path)
                        .with_context(|| format!("reading {}", path.display()))?;
                    parse_signed_policy_lifecycle_checkpoint_witness(&source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("parsing {}", path.display()))
                })
                .collect::<Result<Vec<_>>>()?;
            let public_keys = public_keys
                .iter()
                .map(|path| read_hex_key(path, "trusted policy lifecycle witness public key"))
                .collect::<Result<Vec<_>>>()?;
            let report = verify_policy_lifecycle_checkpoint_witnesses(
                &state,
                &witnesses,
                &public_keys,
                minimum_witnesses,
                evaluated_at_unix,
            )
            .map_err(anyhow::Error::msg)?;
            let document = serde_json::to_string_pretty(&report)? + "\n";
            write_new_file_set(&[(output.as_path(), document.as_str())])?;
            eprintln!(
                "policy lifecycle checkpoint witness quorum: {}/{}",
                report.valid_witnesses, report.minimum_witnesses
            );
            if require_quorum && !report.quorum_met {
                bail!("policy lifecycle checkpoint witness quorum was not met");
            }
        }
        Command::RecordSimulationEvidence {
            declaration,
            electrical_review,
            artifacts,
            output,
            require_passed,
        } => {
            let declaration_source = fs::read_to_string(&declaration)
                .with_context(|| format!("reading {}", declaration.display()))?;
            let declaration_value = parse_simulation_declaration(&declaration_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("parsing {}", declaration.display()))?;
            let review_bytes = fs::read(&electrical_review)
                .with_context(|| format!("reading {}", electrical_review.display()))?;
            let review: ElectricalReview = serde_json::from_slice(&review_bytes)
                .with_context(|| format!("parsing {}", electrical_review.display()))?;
            if review.schema_version != 1 {
                bail!(
                    "unsupported electrical review schema version {}",
                    review.schema_version
                );
            }
            if declaration_value.schematic_sha256 != review.schematic_sha256 {
                bail!(
                    "simulation declaration schematic SHA-256 does not match the electrical review"
                );
            }
            let artifact_values = artifacts
                .iter()
                .map(|path| simulation_artifact(path))
                .collect::<Result<Vec<_>>>()?;
            let evidence = record_simulation_evidence(
                &declaration_value,
                &format!("{:x}", Sha256::digest(&review_bytes)),
                review.approved,
                artifact_values,
            )
            .map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&evidence)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "simulation evidence: {}; {} passed, {} failed assertion(s); electrical review: {}",
                if evidence.passed { "passed" } else { "failed" },
                evidence.counts.passed,
                evidence.counts.failed,
                if evidence.electrical_review_approved {
                    "approved"
                } else {
                    "rejected"
                }
            );
            if require_passed && !evidence.passed {
                bail!(
                    "simulation evidence {} failed its approval gate",
                    evidence.id
                );
            }
        }
        Command::AiReviewRequestSchema { output } => {
            write_or_print_json(&ai_review_request_json_schema(), output.as_ref())?;
        }
        Command::AiReviewResponseSchema { output } => {
            write_or_print_json(&ai_review_response_json_schema(), output.as_ref())?;
        }
        Command::SignedAiApprovalSchema { output } => {
            write_or_print_json(&signed_ai_approval_json_schema(), output.as_ref())?;
        }
        Command::AiApprovalQuorumSchema { output } => {
            write_or_print_json(&ai_approval_quorum_report_json_schema(), output.as_ref())?;
        }
        Command::RoutedAiApprovalQuorumSchema { output } => {
            write_or_print_json(
                &routed_ai_approval_quorum_report_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::SignedHumanEscalationSchema { output } => {
            write_or_print_json(&signed_human_escalation_json_schema(), output.as_ref())?;
        }
        Command::HumanEscalationReportSchema { output } => {
            write_or_print_json(&human_escalation_report_json_schema(), output.as_ref())?;
        }
        Command::ApprovalTransparencyLogSchema { output } => {
            write_or_print_json(&approval_transparency_log_json_schema(), output.as_ref())?;
        }
        Command::SignedApprovalLogCheckpointSchema { output } => {
            write_or_print_json(
                &signed_approval_log_checkpoint_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ApprovalLogVerificationReportSchema { output } => {
            write_or_print_json(
                &approval_log_verification_report_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::SignedApprovalLogWitnessSchema { output } => {
            write_or_print_json(&signed_approval_log_witness_json_schema(), output.as_ref())?;
        }
        Command::ApprovalLogWitnessTrustStateSchema { output } => {
            write_or_print_json(
                &approval_log_witness_trust_state_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::SignedApprovalLogWitnessKeyRotationSchema { output } => {
            write_or_print_json(
                &signed_approval_log_witness_key_rotation_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ApprovalLogAnchorProofSchema { output } => {
            write_or_print_json(&approval_log_anchor_proof_json_schema(), output.as_ref())?;
        }
        Command::ApprovalLogAnchorVerificationReportSchema { output } => {
            write_or_print_json(
                &approval_log_anchor_verification_report_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::ApprovalLogWitnessQuorumReportSchema { output } => {
            write_or_print_json(
                &approval_log_witness_quorum_report_json_schema(),
                output.as_ref(),
            )?;
        }
        Command::RemoteWitnessReceiptSchema { output } => {
            write_or_print_json(&remote_witness_receipt_json_schema(), output.as_ref())?;
        }
        Command::RemotePolicyPackReceiptSchema { output } => {
            write_or_print_json(&remote_policy_pack_receipt_json_schema(), output.as_ref())?;
        }
        Command::PrepareAiReview {
            input,
            electrical_review,
            policy,
            simulation_evidence,
            requirements,
            policy_pack,
            allow_no_simulation,
            output,
            session_output,
        } => {
            let schematic_source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let schematic = import_schematic(&schematic_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("importing {}", input.display()))?;
            let pack = policy_pack
                .as_ref()
                .map(|path| load_policy_pack(path).map(|value| value.0))
                .transpose()?;
            let policy = if let Some(pack) = &pack {
                pack.electrical_policy.clone()
            } else if let Some(path) = policy {
                parse_electrical_policy(
                    &fs::read_to_string(&path)
                        .with_context(|| format!("reading {}", path.display()))?,
                )
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("parsing {}", path.display()))?
            } else {
                ElectricalPolicy::default()
            };
            let review_bytes = fs::read(&electrical_review)
                .with_context(|| format!("reading {}", electrical_review.display()))?;
            let review: ElectricalReview = serde_json::from_slice(&review_bytes)
                .with_context(|| format!("parsing {}", electrical_review.display()))?;
            let evidence = simulation_evidence
                .iter()
                .map(|path| read_described_json::<SimulationEvidence>(path).map(|(value, _)| value))
                .collect::<Result<Vec<_>>>()?;
            let requirements = if let Some(pack) = &pack {
                pack.ai_requirements.clone()
            } else {
                if requirements.is_empty() {
                    bail!("at least one --requirement is required without --policy-pack");
                }
                requirements
                    .iter()
                    .map(|value| parse_ai_requirement(value))
                    .collect::<Result<Vec<_>>>()?
            };
            let request = build_ai_review_request(
                schematic,
                &policy,
                review,
                format!("{:x}", Sha256::digest(&review_bytes)),
                evidence,
                requirements,
                pack.as_ref()
                    .map(|pack| pack.require_simulation_evidence)
                    .unwrap_or(!allow_no_simulation),
            )
            .map_err(anyhow::Error::msg)?;
            let prepared_session = if let Some(session_output) = session_output.as_ref() {
                if session_output.0.as_ref() == output.as_path() {
                    bail!("AI review request and session output paths must differ");
                }
                let ttl_seconds = 3600;
                let issued_at_unix = current_unix_seconds()?;
                let expires_at_unix = issued_at_unix
                    .checked_add(ttl_seconds)
                    .ok_or_else(|| anyhow::anyhow!("AI review session expiration overflowed"))?;
                let mut challenge = [0_u8; 32];
                getrandom::fill(&mut challenge)
                    .context("generating AI review session challenge")?;
                let session = build_ai_review_session(
                    &request,
                    &hex_encode(&challenge),
                    issued_at_unix,
                    expires_at_unix,
                )
                .map_err(anyhow::Error::msg)?;
                Some(session)
            } else {
                None
            };
            fs::write(&output, serde_json::to_string_pretty(&request)?)
                .with_context(|| format!("writing {}", output.display()))?;
            if let (Some(session_output), Some(session)) = (session_output, prepared_session) {
                fs::write(&*session_output, serde_json::to_string_pretty(&session)?)
                    .with_context(|| format!("writing {}", session_output.display()))?;
            }
            eprintln!(
                "AI review request: {} requirement(s), {} simulation evidence item(s)",
                request.requirements.len(),
                request.simulation_evidence.len()
            );
        }
        Command::ApprovalKeygen {
            private_key,
            public_key,
        } => {
            if private_key == public_key {
                bail!("private and public approval key paths must differ");
            }
            if private_key.exists() || public_key.exists() {
                bail!("approval key generation refuses to overwrite an existing file");
            }
            let secret = random_secret_key()?;
            write_new_file(
                &public_key,
                &format!("{}\n", approval_public_key(&secret)),
                false,
            )?;
            write_new_file(&private_key, &format!("{}\n", hex_encode(&secret)), true)?;
            eprintln!(
                "Ed25519 approval keypair written to {} and {}",
                private_key.display(),
                public_key.display()
            );
        }
        Command::SignAiReview {
            request,
            response,
            private_key,
            signer_id,
            session,
            output,
            require_approved,
        } => {
            let (request, _) = read_described_json::<AiReviewRequest>(&request)?;
            let response_source = fs::read_to_string(&response)
                .with_context(|| format!("reading {}", response.display()))?;
            let response = parse_ai_review_response(&response_source)
                .map_err(anyhow::Error::msg)
                .with_context(|| format!("parsing {}", response.display()))?;
            let secret = read_secret_key(&private_key)?;
            let approval = if let Some(path) = session {
                let (session, _) = read_described_json::<AiReviewSession>(&path)?;
                let digest = pcbex_kicad::ai_review_session_sha256(&session, &request)
                    .map_err(anyhow::Error::msg)?;
                sign_ai_review_for_session(&request, &response, &digest, &signer_id, &secret)
                    .map_err(anyhow::Error::msg)?
            } else {
                sign_ai_review(&request, &response, &signer_id, &secret)
                    .map_err(anyhow::Error::msg)?
            };
            fs::write(&output, serde_json::to_string_pretty(&approval)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "signed AI review: {}; {} gate failure(s)",
                if approval.approved {
                    "approved"
                } else {
                    "rejected"
                },
                approval.gate_failures.len()
            );
            if require_approved && !approval.approved {
                bail!("signed AI review did not pass every approval gate");
            }
        }
        Command::VerifyAiApproval {
            approval,
            request,
            response,
            public_key,
            policy_pack,
            session,
            require_approved,
        } => {
            let (approval, _) = read_described_json::<SignedAiApproval>(&approval)?;
            let (request, _) = read_described_json::<AiReviewRequest>(&request)?;
            let (response, _) = read_described_json::<AiReviewResponse>(&response)?;
            let public_key = if let Some(path) = policy_pack {
                let pack = load_policy_pack(&path)?.0;
                validate_ai_request_against_policy_pack(&request, &pack)?;
                let trusted = pack
                    .trusted_approval_keys
                    .iter()
                    .find(|trusted| trusted.signer_id == approval.signer_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "approval signer {:?} is not trusted by policy pack {}",
                            approval.signer_id,
                            pack.id
                        )
                    })?;
                decode_hex_key(&trusted.public_key, "trusted approval public key")?
            } else {
                read_hex_key(
                    public_key
                        .as_deref()
                        .expect("clap requires a public key or policy pack"),
                    "approval public key",
                )?
            };
            if let Some(path) = session {
                let (session, _) = read_described_json::<AiReviewSession>(&path)?;
                let evaluated_at_unix = current_unix_seconds()?;
                let digest =
                    pcbex_kicad::validate_ai_review_session(&session, &request, evaluated_at_unix)
                        .map_err(anyhow::Error::msg)?;
                verify_session_signed_ai_approval(
                    &approval,
                    &request,
                    &response,
                    &public_key,
                    &digest,
                )
                .map_err(anyhow::Error::msg)?;
            } else {
                verify_signed_ai_approval(&approval, &request, &response, &public_key)
                    .map_err(anyhow::Error::msg)?;
            }
            if require_approved && !approval.approved {
                bail!("signature is valid, but the AI review was rejected");
            }
            println!(
                "valid Ed25519 {} from {}",
                if approval.approved {
                    "approval"
                } else {
                    "rejection"
                },
                approval.signer_id
            );
        }
        Command::VerifyAiQuorum {
            request,
            approvals,
            responses,
            policy_pack,
            minimum_approvals,
            minimum_distinct_providers,
            minimum_distinct_models,
            baseline_schematic,
            current_schematic,
            reviewer_routing_policy,
            session,
            output,
            summary_output,
            require_quorum,
        } => {
            if approvals.len() != responses.len() {
                bail!(
                    "--approval and --response counts must match; received {} and {}",
                    approvals.len(),
                    responses.len()
                );
            }
            if summary_output.as_ref().is_some_and(|path| path == &output) {
                bail!("quorum JSON and Markdown output paths must differ");
            }
            let (request, _) = read_described_json::<AiReviewRequest>(&request)?;
            let pack = load_policy_pack(&policy_pack)?.0;
            validate_ai_request_against_policy_pack(&request, &pack)?;

            let mut loaded_approvals = Vec::with_capacity(approvals.len());
            let mut loaded_responses = Vec::with_capacity(responses.len());
            let mut trusted_keys = Vec::with_capacity(approvals.len());
            for (approval_path, response_path) in approvals.iter().zip(&responses) {
                let (approval, _) = read_described_json::<SignedAiApproval>(approval_path)?;
                let response_source = fs::read_to_string(response_path)
                    .with_context(|| format!("reading {}", response_path.display()))?;
                let response = parse_ai_review_response(&response_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("parsing {}", response_path.display()))?;
                let trusted = pack
                    .trusted_approval_keys
                    .iter()
                    .find(|trusted| trusted.signer_id == approval.signer_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "approval signer {:?} is not trusted by policy pack {}",
                            approval.signer_id,
                            pack.id
                        )
                    })?;
                trusted_keys.push(decode_hex_key(
                    &trusted.public_key,
                    "trusted approval public key",
                )?);
                loaded_approvals.push(approval);
                loaded_responses.push(response);
            }
            let candidates = loaded_approvals
                .iter()
                .zip(&loaded_responses)
                .zip(&trusted_keys)
                .map(
                    |((approval, response), trusted_public_key)| AiApprovalQuorumCandidate {
                        approval,
                        response,
                        trusted_public_key,
                    },
                )
                .collect::<Vec<_>>();
            let quorum_policy = AiApprovalQuorumPolicy {
                minimum_approvals,
                minimum_distinct_providers,
                minimum_distinct_models,
            };
            let loaded_session = session
                .as_ref()
                .map(|path| read_described_json::<AiReviewSession>(path).map(|value| value.0))
                .transpose()?;
            let evaluated_at_unix = if loaded_session.is_some() {
                Some(current_unix_seconds()?)
            } else {
                None
            };
            if let (Some(baseline), Some(current), Some(routing_policy)) = (
                baseline_schematic,
                current_schematic,
                reviewer_routing_policy,
            ) {
                let baseline_document = import_schematic(&fs::read_to_string(&baseline)?)
                    .map_err(anyhow::Error::msg)?;
                let current_document =
                    import_schematic(&fs::read_to_string(&current)?).map_err(anyhow::Error::msg)?;
                let routing_policy =
                    parse_schematic_reviewer_routing_policy(&fs::read_to_string(&routing_policy)?)
                        .map_err(anyhow::Error::msg)?;
                let plan =
                    route_schematic_review(&baseline_document, &current_document, &routing_policy)
                        .map_err(anyhow::Error::msg)?;
                if let (Some(session), Some(evaluated_at_unix)) =
                    (loaded_session.as_ref(), evaluated_at_unix)
                {
                    let report = verify_session_routed_ai_approval_quorum(
                        &request,
                        session,
                        evaluated_at_unix,
                        &candidates,
                        quorum_policy,
                        &plan,
                    )
                    .map_err(anyhow::Error::msg)?;
                    fs::write(&output, serde_json::to_string_pretty(&report)?)?;
                    if let Some(path) = summary_output {
                        fs::write(
                            &path,
                            render_session_routed_ai_approval_quorum_summary(&report),
                        )?;
                    }
                    eprintln!(
                        "time-bound routed AI approval quorum: {}",
                        if report.routed_quorum.routed_quorum_met {
                            "approved"
                        } else {
                            "not met"
                        }
                    );
                    if require_quorum && !report.routed_quorum.routed_quorum_met {
                        bail!("routed AI approval quorum did not meet every threshold");
                    }
                } else {
                    let report = verify_routed_ai_approval_quorum(
                        &request,
                        &candidates,
                        quorum_policy,
                        &plan,
                    )
                    .map_err(anyhow::Error::msg)?;
                    fs::write(&output, serde_json::to_string_pretty(&report)?)?;
                    if let Some(path) = summary_output {
                        fs::write(&path, render_routed_ai_approval_quorum_summary(&report))?;
                    }
                    eprintln!(
                        "routed AI approval quorum: {}/{} profile(s), {} global approval(s): {}",
                        report
                            .profiles
                            .iter()
                            .filter(|profile| profile.profile_met)
                            .count(),
                        report.profiles.len(),
                        report.quorum.counts.approvals,
                        if report.routed_quorum_met {
                            "approved"
                        } else {
                            "not met"
                        }
                    );
                    if require_quorum && !report.routed_quorum_met {
                        bail!("routed AI approval quorum did not meet every threshold");
                    }
                }
            } else {
                if let (Some(session), Some(evaluated_at_unix)) =
                    (loaded_session.as_ref(), evaluated_at_unix)
                {
                    let report = verify_session_ai_approval_quorum(
                        &request,
                        session,
                        evaluated_at_unix,
                        &candidates,
                        quorum_policy,
                    )
                    .map_err(anyhow::Error::msg)?;
                    fs::write(&output, serde_json::to_string_pretty(&report)?)?;
                    if let Some(path) = summary_output {
                        fs::write(
                            &path,
                            pcbex_kicad::render_session_ai_approval_quorum_summary(&report),
                        )?;
                    }
                    eprintln!(
                        "time-bound AI approval quorum: {}",
                        if report.quorum.quorum_met {
                            "approved"
                        } else {
                            "not met"
                        }
                    );
                    if require_quorum && !report.quorum.quorum_met {
                        bail!("AI approval quorum did not meet every threshold");
                    }
                } else {
                    let report = verify_ai_approval_quorum(&request, &candidates, quorum_policy)
                        .map_err(anyhow::Error::msg)?;
                    fs::write(&output, serde_json::to_string_pretty(&report)?)?;
                    if let Some(path) = summary_output {
                        fs::write(&path, render_ai_approval_quorum_summary(&report))?;
                    }
                    eprintln!(
                        "AI approval quorum: {} approval(s), {} provider(s), {} model(s): {}",
                        report.counts.approvals,
                        report.counts.distinct_providers,
                        report.counts.distinct_models,
                        if report.quorum_met {
                            "approved"
                        } else {
                            "not met"
                        }
                    );
                    if require_quorum && !report.quorum_met {
                        bail!("AI approval quorum did not meet every threshold");
                    }
                }
            }
        }
        Command::SignHumanEscalation {
            request,
            session,
            ai_quorum,
            private_key,
            signer_id,
            decision,
            reason,
            ticket,
            output,
        } => {
            let (request, _) = read_described_json::<AiReviewRequest>(&request)?;
            let (session, _) = read_described_json::<AiReviewSession>(&session)?;
            let (evidence, _) = read_described_json::<SessionAiQuorumEvidence>(&ai_quorum)?;
            let secret = read_hex_key(&private_key, "human escalation private key")?;
            let signed = sign_human_escalation(
                &request,
                &session,
                &evidence,
                decision.into(),
                &reason,
                &ticket,
                &signer_id,
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&signed)?, false)?;
            eprintln!(
                "signed human escalation for {} as {}",
                signed.ai_quorum_sha256, signed.signer_id
            );
        }
        Command::VerifyHumanEscalation {
            request,
            session,
            ai_quorum,
            escalations,
            policy_pack,
            minimum_approvals,
            output,
            summary_output,
            require_approved,
        } => {
            if summary_output
                .as_ref()
                .is_some_and(|summary| summary.0.as_ref() == output.0.as_ref())
            {
                bail!("human escalation JSON and Markdown output paths must differ");
            }
            let (request, _) = read_described_json::<AiReviewRequest>(&request)?;
            let (session, _) = read_described_json::<AiReviewSession>(&session)?;
            let (evidence, _) = read_described_json::<SessionAiQuorumEvidence>(&ai_quorum)?;
            let (pack, _) = load_policy_pack(&policy_pack)?;
            let signed = escalations
                .iter()
                .map(|path| read_described_json::<SignedHumanEscalation>(path).map(|value| value.0))
                .collect::<Result<Vec<_>>>()?;
            let mut trusted_keys = Vec::with_capacity(signed.len());
            for escalation in &signed {
                let trusted = pack
                    .trusted_human_escalation_keys
                    .iter()
                    .find(|trusted| trusted.signer_id == escalation.signer_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "human escalation signer {:?} is not trusted by policy pack {}",
                            escalation.signer_id,
                            policy_pack.display()
                        )
                    })?;
                trusted_keys.push(decode_hex_key(
                    &trusted.public_key,
                    "trusted human escalation public key",
                )?);
            }
            let candidates = signed
                .iter()
                .zip(&trusted_keys)
                .map(
                    |(escalation, trusted_public_key)| HumanEscalationCandidate {
                        escalation,
                        trusted_public_key,
                    },
                )
                .collect::<Vec<_>>();
            let report = verify_human_escalation(
                &request,
                &session,
                &evidence,
                current_unix_seconds()?,
                &candidates,
                HumanEscalationPolicy { minimum_approvals },
            )
            .map_err(anyhow::Error::msg)?;
            fs::write(&*output, serde_json::to_string_pretty(&report)?)?;
            if let Some(path) = summary_output {
                fs::write(&*path, render_human_escalation_summary(&report))?;
            }
            eprintln!(
                "human escalation: {}/{} approval(s), {} rejection(s): {}",
                report.approvals,
                report.policy.minimum_approvals,
                report.rejections,
                if report.escalation_approved {
                    "approved"
                } else {
                    "not approved"
                }
            );
            if require_approved && !report.escalation_approved {
                bail!("human escalation did not receive dual-control approval");
            }
        }
        Command::InitApprovalLog { log_id, output } => {
            let log = new_approval_transparency_log(&log_id).map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&log)?, false)?;
            eprintln!("initialized approval transparency log {log_id}");
        }
        Command::AppendApprovalLog {
            log,
            artifact,
            kind,
            recorded_at_unix,
            output,
        } => {
            if log.0.as_ref() == output.0.as_ref() {
                bail!("approval log input and output paths must differ");
            }
            let (mut log, _) = read_described_json::<ApprovalTransparencyLog>(&log)?;
            let event = approval_event_descriptor(kind, &artifact)?;
            let digest = append_approval_transparency_event(
                &mut log,
                event,
                recorded_at_unix.unwrap_or(current_unix_seconds()?),
            )
            .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&log)?, false)?;
            eprintln!(
                "appended approval transparency entry {} at sequence {}",
                digest,
                log.entries.len() - 1
            );
        }
        Command::SignApprovalLog {
            log,
            private_key,
            signer_id,
            output,
        } => {
            if log.0.as_ref() == output.0.as_ref() {
                bail!("approval log and checkpoint output paths must differ");
            }
            let (log, _) = read_described_json::<ApprovalTransparencyLog>(&log)?;
            let secret = read_hex_key(&private_key, "approval checkpoint private key")?;
            let checkpoint = sign_approval_log_checkpoint(&log, &signer_id, &secret)
                .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&checkpoint)?, false)?;
            eprintln!(
                "signed approval log {} at {} entr{}",
                checkpoint.log_id,
                checkpoint.entry_count,
                if checkpoint.entry_count == 1 {
                    "y"
                } else {
                    "ies"
                }
            );
        }
        Command::VerifyApprovalLog {
            log,
            checkpoint,
            public_key,
            output,
        } => {
            if output.0.as_ref() == log.0.as_ref() || output.0.as_ref() == checkpoint.0.as_ref() {
                bail!("approval log verification output must use a separate path");
            }
            let (log, _) = read_described_json::<ApprovalTransparencyLog>(&log)?;
            let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(&checkpoint)?;
            let trusted = read_hex_key(&public_key, "trusted approval checkpoint public key")?;
            let report = verify_approval_log_checkpoint(&log, &checkpoint, &trusted)
                .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&report)?, false)?;
            eprintln!(
                "verified approval transparency log {} with {} entries",
                report.log_id, report.entry_count
            );
        }
        Command::WitnessApprovalLog {
            checkpoint,
            private_key,
            witness_id,
            observed_at_unix,
            output,
        } => {
            if checkpoint.0.as_ref() == output.0.as_ref() {
                bail!("approval checkpoint and witness output paths must differ");
            }
            let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(&checkpoint)?;
            let secret = read_hex_key(&private_key, "approval-log witness private key")?;
            let witness = sign_approval_log_witness(
                &checkpoint,
                &witness_id,
                observed_at_unix.unwrap_or(current_unix_seconds()?),
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&witness)?, false)?;
            eprintln!(
                "witnessed approval log {} as {}",
                witness.log_id, witness.witness_id
            );
        }
        Command::InitApprovalLogWitnessTrust {
            witness_id,
            public_key,
            output,
        } => {
            require_distinct_outputs(
                [Some(public_key.0.as_ref()), Some(output.0.as_ref())],
                "witness trust initialization",
            )?;
            let key = read_hex_key(&public_key, "initial approval-log witness public key")?;
            let state = new_approval_log_witness_trust_state(&witness_id, &key)
                .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&state)?, false)?;
            eprintln!("initialized witness trust {witness_id} at generation 0");
        }
        Command::SignApprovalLogWitnessKeyRotation {
            trust_state,
            old_private_key,
            new_private_key,
            rotated_at_unix,
            output,
        } => {
            require_distinct_outputs(
                [Some(trust_state.0.as_ref()), Some(output.0.as_ref())],
                "witness key rotation",
            )?;
            let (state, _) = read_described_json::<ApprovalLogWitnessTrustState>(&trust_state)?;
            let old_secret =
                read_hex_key(&old_private_key, "current approval-log witness private key")?;
            let new_secret =
                read_hex_key(&new_private_key, "new approval-log witness private key")?;
            let rotation = sign_approval_log_witness_key_rotation(
                &state,
                &old_secret,
                &new_secret,
                rotated_at_unix.unwrap_or(current_unix_seconds()?),
            )
            .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&rotation)?, false)?;
            eprintln!(
                "signed witness key rotation {} generation {} -> {}",
                rotation.witness_id, rotation.from_generation, rotation.to_generation
            );
        }
        Command::ApplyApprovalLogWitnessKeyRotation {
            trust_state,
            rotation,
            output,
            public_key_output,
        } => {
            require_distinct_outputs(
                [
                    Some(trust_state.0.as_ref()),
                    Some(rotation.0.as_ref()),
                    Some(output.0.as_ref()),
                    Some(public_key_output.0.as_ref()),
                ],
                "witness key rotation",
            )?;
            let (state, _) = read_described_json::<ApprovalLogWitnessTrustState>(&trust_state)?;
            let (rotation, _) =
                read_described_json::<SignedApprovalLogWitnessKeyRotation>(&rotation)?;
            let next = apply_approval_log_witness_key_rotation(&state, &rotation)
                .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&next)?, false)?;
            if let Err(error) = write_new_file(
                &public_key_output,
                &format!("{}\n", next.current_public_key),
                false,
            ) {
                fs::remove_file(output.0.as_ref()).ok();
                return Err(error);
            }
            eprintln!(
                "trusted witness key {} at generation {}",
                next.witness_id, next.generation
            );
        }
        Command::ExportApprovalLogWitnessPublicKey {
            trust_state,
            output,
        } => {
            require_distinct_outputs(
                [Some(trust_state.0.as_ref()), Some(output.0.as_ref())],
                "witness trust export",
            )?;
            let (state, _) = read_described_json::<ApprovalLogWitnessTrustState>(&trust_state)?;
            approval_log_witness_trusted_public_key(&state).map_err(anyhow::Error::msg)?;
            write_new_file(&output, &format!("{}\n", state.current_public_key), false)?;
            eprintln!(
                "exported witness key {} at generation {}",
                state.witness_id, state.generation
            );
        }
        Command::CreateApprovalLogAnchor {
            checkpoint,
            log_checkpoints,
            leaf_index,
            log_id,
            private_key,
            observed_at_unix,
            output,
        } => {
            if output.0.as_ref() == checkpoint.0.as_ref()
                || output.0.as_ref() == private_key.0.as_ref()
                || log_checkpoints
                    .iter()
                    .any(|path| path.as_path() == output.0.as_ref())
            {
                bail!("approval-log anchor output must use a separate path");
            }
            let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(&checkpoint)?;
            let checkpoint_digests = log_checkpoints
                .iter()
                .map(|path| {
                    let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(path)?;
                    signed_approval_log_checkpoint_sha256(&checkpoint).map_err(anyhow::Error::msg)
                })
                .collect::<Result<Vec<_>>>()?;
            let secret = read_hex_key(&private_key, "approval public-log private key")?;
            let proof = create_approval_log_anchor_proof(
                &checkpoint,
                &checkpoint_digests,
                leaf_index,
                &log_id,
                observed_at_unix.unwrap_or(current_unix_seconds()?),
                &secret,
            )
            .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&proof)?, false)?;
            eprintln!(
                "anchored approval checkpoint at {}/{} in {}",
                proof.leaf_index, proof.tree_head.tree_size, proof.tree_head.log_id
            );
        }
        Command::VerifyApprovalLogAnchor {
            checkpoint,
            proof,
            public_key,
            output,
        } => {
            require_distinct_outputs(
                [
                    Some(checkpoint.0.as_ref()),
                    Some(proof.0.as_ref()),
                    Some(public_key.0.as_ref()),
                    Some(output.0.as_ref()),
                ],
                "approval-log anchor verification",
            )?;
            let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(&checkpoint)?;
            let (proof, _) = read_described_json::<ApprovalLogAnchorProof>(&proof)?;
            let trusted = read_hex_key(&public_key, "trusted approval public-log key")?;
            let report = verify_approval_log_anchor_proof(&checkpoint, &proof, &trusted)
                .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&report)?, false)?;
            eprintln!(
                "verified approval checkpoint anchor {}/{} in {}",
                report.leaf_index, report.tree_size, report.log_id
            );
        }
        Command::VerifyApprovalLogWitnesses {
            checkpoint,
            witnesses,
            public_keys,
            minimum_witnesses,
            output,
            require_quorum,
        } => {
            if witnesses.len() != public_keys.len() {
                bail!("each --witness requires one positionally paired --public-key");
            }
            let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(&checkpoint)?;
            let witness_values = witnesses
                .iter()
                .map(|path| {
                    read_described_json::<SignedApprovalLogWitness>(path).map(|value| value.0)
                })
                .collect::<Result<Vec<_>>>()?;
            let trusted_keys = public_keys
                .iter()
                .map(|path| read_hex_key(path, "trusted approval-log witness public key"))
                .collect::<Result<Vec<_>>>()?;
            let candidates = witness_values.iter().zip(&trusted_keys).collect::<Vec<_>>();
            let report =
                verify_approval_log_witness_quorum(&checkpoint, &candidates, minimum_witnesses)
                    .map_err(anyhow::Error::msg)?;
            write_new_file(&output, &serde_json::to_string_pretty(&report)?, false)?;
            eprintln!(
                "approval-log witnesses: {}/{}; quorum {}",
                report.valid_witnesses,
                report.minimum_witnesses,
                if report.quorum_met { "met" } else { "not met" }
            );
            if require_quorum && !report.quorum_met {
                bail!("approval-log witness quorum was not met");
            }
        }
        Command::RequestApprovalLogWitness {
            checkpoint,
            endpoint,
            public_key,
            bearer_token_env,
            timeout_seconds,
            output,
            receipt_output,
            allow_http_loopback,
        } => {
            require_distinct_outputs(
                [
                    Some(checkpoint.0.as_ref()),
                    Some(output.0.as_ref()),
                    Some(receipt_output.0.as_ref()),
                ],
                "remote witness",
            )?;
            let (checkpoint, _) = read_described_json::<SignedApprovalLogCheckpoint>(&checkpoint)?;
            let trusted = read_hex_key(&public_key, "trusted remote witness public key")?;
            let (witness, receipt) = request_remote_witness(
                &checkpoint,
                &endpoint,
                &trusted,
                bearer_token_env.as_deref(),
                timeout_seconds,
                allow_http_loopback,
            )
            .map_err(anyhow::Error::msg)?;
            let witness_json = serde_json::to_string_pretty(&witness)?;
            let receipt_json = serde_json::to_string_pretty(&receipt)?;
            write_new_file(&output, &witness_json, false)?;
            if let Err(error) = write_new_file(&receipt_output, &receipt_json, false) {
                fs::remove_file(output.0.as_ref()).ok();
                return Err(error);
            }
            eprintln!(
                "verified remote approval-log witness {} for {}",
                witness.witness_id, witness.log_id
            );
        }
        Command::DfmProfiles { output } => {
            let profiles = serde_json::to_string_pretty(&dfm_profiles())?;
            if let Some(path) = output {
                fs::write(path, profiles)?;
            } else {
                println!("{profiles}");
            }
        }
        Command::DfmProfileSchema { output } => {
            let schema = serde_json::to_string_pretty(&dfm_profile_json_schema())?;
            if let Some(path) = output {
                fs::write(path, schema)?;
            } else {
                println!("{schema}");
            }
        }
        Command::ValidateDfmProfile { input, output } => {
            let (profile, _) = resolve_dfm_profile(None, Some(&input))?;
            let normalized = serde_json::to_string_pretty(
                &profile.expect("external profile resolution always returns a profile"),
            )?;
            if let Some(path) = output {
                fs::write(path, normalized)?;
            } else {
                println!("{normalized}");
            }
        }
        Command::PolicyPackSchema { output } => {
            write_or_print_json(&policy_pack_json_schema(), output.as_ref())?;
        }
        Command::ValidatePolicyPack { input, output } => {
            let pack = load_policy_pack(&input)?.0;
            write_or_print_json(&serde_json::to_value(pack)?, output.as_ref())?;
        }
        Command::SignedPolicyPackSchema { output } => {
            write_or_print_json(&signed_policy_pack_json_schema(), output.as_ref())?;
        }
        Command::PolicyTrustStateSchema { output } => {
            write_or_print_json(&policy_trust_state_json_schema(), output.as_ref())?;
        }
        Command::PolicyKeygen {
            private_key,
            public_key,
        } => {
            if private_key == public_key {
                bail!("private and public policy key paths must differ");
            }
            if private_key.exists() || public_key.exists() {
                bail!("policy key generation refuses to overwrite an existing file");
            }
            let secret = random_secret_key()?;
            let public = approval_public_key(&secret);
            write_new_file(&private_key, &format!("{}\n", hex_encode(&secret)), true)?;
            if let Err(error) = write_new_file(&public_key, &format!("{public}\n"), false) {
                let _ = fs::remove_file(&private_key);
                return Err(error);
            }
            eprintln!(
                "created policy signing key {} and public key {}",
                private_key.display(),
                public_key.display()
            );
        }
        Command::SignPolicyPack {
            input,
            private_key,
            signer_id,
            output,
        } => {
            let pack = load_policy_pack(&input)?.0;
            let secret = read_hex_key(&private_key, "policy signing private key")?;
            let signed = sign_policy_pack(pack, &signer_id, &secret)
                .map_err(anyhow::Error::msg)
                .context("signing organization policy pack")?;
            write_new_file(
                &output,
                &format!("{}\n", serde_json::to_string_pretty(&signed)?),
                false,
            )?;
            eprintln!(
                "signed policy pack {} revision {} as {}",
                signed.policy_pack.id, signed.policy_pack.revision, signed.signer_id
            );
        }
        Command::VerifyPolicyPack {
            input,
            public_key,
            baseline_state,
            state_output,
            output,
        } => {
            if output.is_some() && output == state_output {
                bail!("verified policy pack and trust-state output paths must differ");
            }
            for path in output.iter().chain(state_output.iter()) {
                if path.exists() {
                    bail!("refusing to overwrite existing output {}", path.display());
                }
            }
            let signed = load_signed_policy_pack(&input)?;
            let public_key = read_hex_key(&public_key, "trusted policy public key")?;
            verify_signed_policy_pack(&signed, &public_key)
                .map_err(anyhow::Error::msg)
                .context("verifying signed organization policy pack")?;
            let baseline = baseline_state
                .as_deref()
                .map(load_policy_trust_state)
                .transpose()?;
            let state = advance_policy_trust_state(&signed, baseline.as_ref())
                .map_err(anyhow::Error::msg)
                .context("checking monotonic organization policy state")?;
            let normalized = format!("{}\n", serde_json::to_string_pretty(&signed.policy_pack)?);
            if let Some(path) = output {
                write_new_file(&path, &normalized, false)?;
            } else {
                print!("{normalized}");
            }
            if let Some(path) = state_output {
                write_new_file(
                    &path,
                    &format!("{}\n", serde_json::to_string_pretty(&state)?),
                    false,
                )?;
            }
            eprintln!(
                "verified policy pack {} revision {} signed by {}",
                signed.policy_pack.id, signed.policy_pack.revision, signed.signer_id
            );
        }
        Command::FetchPolicyPack {
            endpoint,
            public_key,
            baseline_state,
            bearer_token_env,
            timeout_seconds,
            signed_output,
            output,
            state_output,
            receipt_output,
            allow_http_loopback,
        } => {
            let mut paths = vec![
                public_key.0.as_ref(),
                signed_output.0.as_ref(),
                output.0.as_ref(),
                state_output.0.as_ref(),
                receipt_output.0.as_ref(),
            ];
            if let Some(baseline) = &baseline_state {
                paths.push(baseline.0.as_ref());
            }
            require_distinct_outputs(paths.into_iter().map(Some), "remote policy pack")?;
            for path in [
                signed_output.0.as_ref(),
                output.0.as_ref(),
                state_output.0.as_ref(),
                receipt_output.0.as_ref(),
            ] {
                if path.exists() {
                    bail!("refusing to overwrite existing output {}", path.display());
                }
            }
            let trusted = read_hex_key(&public_key, "trusted policy registry public key")?;
            let baseline = baseline_state
                .as_deref()
                .map(load_policy_trust_state)
                .transpose()?;
            let fetched = fetch_remote_policy_pack(
                &endpoint,
                &trusted,
                baseline.as_ref(),
                bearer_token_env.as_deref(),
                timeout_seconds,
                allow_http_loopback,
            )
            .map_err(anyhow::Error::msg)?;
            let signed_json = format!("{}\n", serde_json::to_string_pretty(&fetched.signed)?);
            let policy_json = format!("{}\n", serde_json::to_string_pretty(&fetched.policy_pack)?);
            let state_json = format!("{}\n", serde_json::to_string_pretty(&fetched.trust_state)?);
            let receipt_json = format!("{}\n", serde_json::to_string_pretty(&fetched.receipt)?);
            write_new_file_set(&[
                (signed_output.0.as_ref(), signed_json.as_str()),
                (output.0.as_ref(), policy_json.as_str()),
                (state_output.0.as_ref(), state_json.as_str()),
                (receipt_output.0.as_ref(), receipt_json.as_str()),
            ])?;
            eprintln!(
                "fetched and verified policy pack {} revision {} signed by {}",
                fetched.policy_pack.id, fetched.policy_pack.revision, fetched.signed.signer_id
            );
        }
        Command::Migrate { input, output } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let migrated = migrate_board_json(&source).map_err(anyhow::Error::msg)?;
            parse_board_json(&serde_json::to_string(&migrated)?).map_err(anyhow::Error::msg)?;
            fs::write(output, serde_json::to_string_pretty(&migrated)?)?;
        }
        Command::Route {
            input,
            output,
            svg,
            allow_unrouted,
        } => {
            let (board, report) = route_board(&read(&input)?).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&board)?)?;
            if let Some(path) = svg {
                fs::write(path, render_svg(&board))?;
            }
            eprintln!(
                "preserved: {}; routed: {}; rerouted: {}; unrouted: {}; rip-ups: {}; shoves: {}; escaped nets: {}; return vias: {}; optimized segments: {}; rounded corners: {}; parallel candidates: {}; workers: {}; fallbacks: {}; expanded states: {}; passes: {}",
                report.preserved.len(),
                report.routed.len(),
                report.rerouted.len(),
                report.unrouted.len(),
                report.ripup_events,
                report.shove_events,
                report.escaped_nets,
                report.generated_return_vias,
                report.optimized_segments,
                report.rounded_corners,
                report.parallel_candidates,
                report.parallel_workers,
                report.parallel_fallbacks,
                report.expanded_states,
                report.reroute_passes
            );
            if !allow_unrouted && !report.unrouted.is_empty() {
                bail!("unrouted nets: {}", report.unrouted.join(", "))
            }
            ensure_clean(&board)?;
        }
        Command::RouteCandidates {
            input,
            output_dir,
            candidates,
            workers,
            router_workers,
            allow_unrouted,
        } => {
            let results = route_candidates(
                &read(&input)?,
                &RoutingCandidateOptions {
                    candidates,
                    workers,
                    router_workers,
                },
            )
            .map_err(anyhow::Error::msg)?;
            write_routing_candidate_reports(&output_dir, &results)?;
            eprintln!(
                "generated {} routing candidates ({} unique); Pareto front: {}; selected: {}",
                results.candidates.len(),
                results
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.duplicate_of.is_none())
                    .count(),
                results.pareto_front.len(),
                results.selected_candidate_id
            );
            if !allow_unrouted && results.selected().quality.unrouted_nets != 0 {
                bail!(
                    "selected routing candidate has {} unrouted net(s)",
                    results.selected().quality.unrouted_nets
                )
            }
            ensure_clean(&results.selected().board)?;
        }
        Command::Repair {
            input,
            output,
            net_ids,
            svg,
        } => {
            let board = read(&input)?;
            let selected = if net_ids.is_empty() {
                repairable_net_ids(&board)
            } else {
                net_ids.into_iter().collect()
            };
            let (repaired, report) =
                repair_routes(&board, &selected).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&repaired)?)?;
            if let Some(path) = svg {
                fs::write(path, render_svg(&repaired))?;
            }
            eprintln!(
                "repaired: {}; locked: {}",
                report.rerouted.join(", "),
                report.preserved.join(", ")
            );
        }
        Command::Quality {
            input,
            output,
            format,
            baseline,
            max_total_length_nm,
            max_vias,
            max_unrouted,
        } => {
            let quality = routing_quality(&read(&input)?);
            let mut regressions = baseline
                .map(|path| -> Result<Vec<String>> {
                    let baseline: RoutingQuality = serde_json::from_str(
                        &fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    )
                    .with_context(|| format!("parsing {}", path.display()))?;
                    Ok(quality.regressions_against(&baseline))
                })
                .transpose()?
                .unwrap_or_default();
            if max_total_length_nm.is_some_and(|limit| quality.total_length_nm > limit) {
                regressions.push(format!(
                    "total length {} exceeds {} nm",
                    quality.total_length_nm,
                    max_total_length_nm.unwrap()
                ));
            }
            if max_vias.is_some_and(|limit| quality.total_vias > limit) {
                regressions.push(format!(
                    "via count {} exceeds {}",
                    quality.total_vias,
                    max_vias.unwrap()
                ));
            }
            if max_unrouted.is_some_and(|limit| quality.unrouted_nets > limit) {
                regressions.push(format!(
                    "unrouted-net count {} exceeds {}",
                    quality.unrouted_nets,
                    max_unrouted.unwrap()
                ));
            }
            let rendered = match format {
                QualityFormat::Json => serde_json::to_string_pretty(&quality)?,
                QualityFormat::Sarif => serde_json::to_string_pretty(&serde_json::json!({
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [{
                        "tool": {"driver": {
                            "name": "pcbex quality",
                            "rules": [{"id": "routing_quality_regression"}]
                        }},
                        "results": regressions.iter().map(|message| serde_json::json!({
                            "ruleId": "routing_quality_regression",
                            "level": "error",
                            "message": {"text": message}
                        })).collect::<Vec<_>>()
                    }]
                }))?,
            };
            if let Some(path) = output {
                fs::write(path, rendered)?;
            } else {
                println!("{rendered}");
            }
            if !regressions.is_empty() {
                bail!("routing quality failed: {}", regressions.join("; "))
            }
        }
        Command::AnalyzeKicad {
            input,
            project,
            rules_file,
            output_dir,
            grid_mm,
            width_mm,
            clearance_mm,
            via_diameter_mm,
            via_drill_mm,
            bend_cost,
            via_cost,
            fab,
            fab_profile,
            policy_pack,
            fail_on_violations,
        } => {
            let input_bytes =
                fs::read(&input).with_context(|| format!("reading {}", input.display()))?;
            let source = std::str::from_utf8(&input_bytes)
                .with_context(|| format!("decoding {} as UTF-8", input.display()))?;
            let rules = Rules {
                grid_nm: to_nm(grid_mm, "grid")?,
                track_width_nm: to_nm(width_mm, "track width")?,
                clearance_nm: to_nm(clearance_mm, "clearance")?,
                via_diameter_nm: to_nm(via_diameter_mm, "via diameter")?,
                via_drill_nm: to_nm(via_drill_mm, "via drill")?,
                bend_cost,
                via_cost,
            };
            if rules.via_drill_nm >= rules.via_diameter_nm {
                bail!("via drill must be smaller than via diameter");
            }
            let mut imported = import_kicad(source, rules.clone()).map_err(anyhow::Error::msg)?;

            let project = project.or_else(|| {
                let candidate = input.with_extension("kicad_pro");
                candidate.exists().then_some(candidate)
            });
            let project_descriptor = project
                .as_ref()
                .map(|path| -> Result<InputDescriptor> {
                    let bytes =
                        fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                    let project_source = std::str::from_utf8(&bytes)
                        .with_context(|| format!("decoding {} as UTF-8", path.display()))?;
                    apply_project_net_settings(&mut imported.board, project_source)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| format!("importing rules from {}", path.display()))?;
                    Ok(input_descriptor(path, &bytes))
                })
                .transpose()?;

            let rules_file = rules_file.or_else(|| {
                let candidate = input.with_extension("kicad_dru");
                candidate.exists().then_some(candidate)
            });
            let mut applied_custom_rules = 0;
            let rules_descriptor = rules_file
                .as_ref()
                .map(|path| -> Result<InputDescriptor> {
                    let bytes =
                        fs::read(path).with_context(|| format!("reading {}", path.display()))?;
                    let rules_source = std::str::from_utf8(&bytes)
                        .with_context(|| format!("decoding {} as UTF-8", path.display()))?;
                    applied_custom_rules =
                        apply_custom_design_rules(&mut imported.board, rules_source)
                            .map_err(anyhow::Error::msg)
                            .with_context(|| {
                                format!("importing custom rules from {}", path.display())
                            })?;
                    Ok(input_descriptor(path, &bytes))
                })
                .transpose()?;
            let policy_pack = policy_pack
                .as_ref()
                .map(|path| load_policy_pack(path))
                .transpose()?;
            let (mut dfm_profile, dfm_profile_file) =
                resolve_dfm_profile(fab.as_deref(), fab_profile.as_deref())?;
            if let Some((pack, _)) = &policy_pack {
                dfm_profile = Some(pack.dfm_profile.clone());
            }
            if let Some(profile) = &dfm_profile {
                apply_dfm_profile(&mut imported.board, profile);
            }

            let report = check_board(&imported.board);
            let quality = routing_quality(&imported.board);
            let summary = render_analysis_summary(&quality, &report);
            let artifacts = vec![
                "board.json".to_string(),
                "board.svg".to_string(),
                "checks.json".to_string(),
                "quality.json".to_string(),
                "report.sarif".to_string(),
                "summary.md".to_string(),
                "run.json".to_string(),
            ];
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            fs::write(
                output_dir.join("board.json"),
                serde_json::to_string_pretty(&imported.board)?,
            )?;
            fs::write(output_dir.join("board.svg"), render_svg(&imported.board))?;
            fs::write(
                output_dir.join("checks.json"),
                serde_json::to_string_pretty(&report)?,
            )?;
            fs::write(
                output_dir.join("quality.json"),
                serde_json::to_string_pretty(&quality)?,
            )?;
            fs::write(
                output_dir.join("report.sarif"),
                serde_json::to_string_pretty(&check_report_to_sarif(&report))?,
            )?;
            fs::write(output_dir.join("summary.md"), summary)?;
            let manifest = RunManifest {
                schema_version: 1,
                engine: "pcbex".to_string(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                command: "analyze-kicad".to_string(),
                input: input_descriptor(&input, &input_bytes),
                project: project_descriptor,
                rules_file: rules_descriptor,
                dfm_profile_file,
                policy_pack_file: policy_pack.as_ref().map(|value| InputDescriptor {
                    path: value.1.path.clone(),
                    bytes: value.1.bytes,
                    sha256: value.1.sha256.clone(),
                }),
                configuration: AnalysisConfiguration {
                    rules: imported.board.rules.clone(),
                    project_settings_loaded: project.is_some(),
                    applied_custom_rules,
                    dfm_profile,
                    organization_policy_pack: policy_pack.as_ref().map(|value| value.0.id.clone()),
                },
                result: AnalysisResult {
                    clean: report.is_clean(),
                    violations: report.violations.len(),
                    routed_nets: quality.routed_nets,
                    unrouted_nets: quality.unrouted_nets,
                    total_length_nm: quality.total_length_nm,
                    total_vias: quality.total_vias,
                },
                artifacts,
            };
            fs::write(
                output_dir.join("run.json"),
                serde_json::to_string_pretty(&manifest)?,
            )?;
            eprintln!(
                "analysis written to {}: {} violation(s), {} routed, {} unrouted",
                output_dir.display(),
                report.violations.len(),
                quality.routed_nets,
                quality.unrouted_nets
            );
            if fail_on_violations && !report.is_clean() {
                bail!(
                    "KiCad analysis found {} violation(s)",
                    report.violations.len()
                );
            }
        }
        Command::CompareAnalysis {
            baseline_dir,
            current_dir,
            output_dir,
            fail_on_regressions,
        } => {
            let (baseline_quality, baseline_quality_input) =
                read_described_json::<RoutingQuality>(&baseline_dir.join("quality.json"))?;
            let (baseline_checks, baseline_checks_input) =
                read_described_json::<pcbex_core::checking::CheckReport>(
                    &baseline_dir.join("checks.json"),
                )?;
            let (current_quality, current_quality_input) =
                read_described_json::<RoutingQuality>(&current_dir.join("quality.json"))?;
            let (current_checks, current_checks_input) =
                read_described_json::<pcbex_core::checking::CheckReport>(
                    &current_dir.join("checks.json"),
                )?;
            let delta = AnalysisDelta::between(
                &baseline_quality,
                &baseline_checks,
                &current_quality,
                &current_checks,
            );
            let regression = delta.is_regression();
            let artifacts = vec![
                "delta.json".to_string(),
                "report.sarif".to_string(),
                "run.json".to_string(),
                "summary.md".to_string(),
            ];
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            fs::write(
                output_dir.join("delta.json"),
                serde_json::to_string_pretty(&delta)?,
            )?;
            fs::write(
                output_dir.join("report.sarif"),
                serde_json::to_string_pretty(&analysis_delta_to_sarif(&delta))?,
            )?;
            fs::write(
                output_dir.join("summary.md"),
                render_comparison_summary(&delta),
            )?;
            let manifest = ComparisonManifest {
                schema_version: 1,
                engine: "pcbex".to_string(),
                engine_version: env!("CARGO_PKG_VERSION").to_string(),
                command: "compare-analysis".to_string(),
                baseline: ComparisonInputs {
                    quality: baseline_quality_input,
                    checks: baseline_checks_input,
                },
                current: ComparisonInputs {
                    quality: current_quality_input,
                    checks: current_checks_input,
                },
                regression,
                artifacts,
            };
            fs::write(
                output_dir.join("run.json"),
                serde_json::to_string_pretty(&manifest)?,
            )?;
            eprintln!(
                "comparison written to {}: {} quality regression(s), {} new violation(s), {} resolved violation(s)",
                output_dir.display(),
                delta.quality_regressions.len(),
                delta.new_violations.len(),
                delta.resolved_violations.len()
            );
            if fail_on_regressions && regression {
                bail!("analysis comparison found regressions");
            }
        }
        Command::RouteKicad {
            input,
            project,
            rules_file,
            output,
            grid_mm,
            width_mm,
            clearance_mm,
            via_diameter_mm,
            via_drill_mm,
            bend_cost,
            via_cost,
            fab,
            fab_profile,
            policy_pack,
            svg,
            json_output,
            drc,
            allow_unrouted,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let rules = Rules {
                grid_nm: to_nm(grid_mm, "grid")?,
                track_width_nm: to_nm(width_mm, "track width")?,
                clearance_nm: to_nm(clearance_mm, "clearance")?,
                via_diameter_nm: to_nm(via_diameter_mm, "via diameter")?,
                via_drill_nm: to_nm(via_drill_mm, "via drill")?,
                bend_cost,
                via_cost,
            };
            if rules.via_drill_nm >= rules.via_diameter_nm {
                bail!("via drill must be smaller than via diameter");
            }
            let mut imported = import_kicad(&source, rules).map_err(anyhow::Error::msg)?;
            let project = project.or_else(|| {
                let candidate = input.with_extension("kicad_pro");
                candidate.exists().then_some(candidate)
            });
            if let Some(path) = project {
                let project_source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                apply_project_net_settings(&mut imported.board, &project_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("importing rules from {}", path.display()))?;
            }
            let rules_file = rules_file.or_else(|| {
                let candidate = input.with_extension("kicad_dru");
                candidate.exists().then_some(candidate)
            });
            if let Some(path) = rules_file {
                let rules_source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                let applied = apply_custom_design_rules(&mut imported.board, &rules_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("importing custom rules from {}", path.display()))?;
                eprintln!(
                    "applied {applied} routing constraints from {}",
                    path.display()
                );
            }
            let profile = if let Some(path) = policy_pack {
                Some(load_policy_pack(&path)?.0.dfm_profile)
            } else {
                resolve_dfm_profile(fab.as_deref(), fab_profile.as_deref())?.0
            };
            if let Some(profile) = profile {
                apply_dfm_profile(&mut imported.board, &profile);
                eprintln!("applied fabrication profile {}", profile.id);
            }
            let (board, report) = route_board(&imported.board).map_err(anyhow::Error::msg)?;
            fs::write(
                &output,
                imported
                    .write_routes(&board.routes)
                    .map_err(anyhow::Error::msg)?,
            )
            .with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = svg {
                fs::write(path, render_svg(&board))?;
            }
            if let Some(path) = json_output {
                fs::write(
                    path,
                    serde_json::to_string_pretty(&serde_json::json!({
                        "origin": imported.origin(),
                        "nets": board.nets.iter().map(|net| serde_json::json!({
                            "id": net.id,
                            "name": net.name,
                        })).collect::<Vec<_>>(),
                        "routes": board.routes,
                    }))?,
                )?;
            }
            eprintln!(
                "preserved: {}; routed: {}; rerouted: {}; unrouted: {}; rip-ups: {}; shoves: {}; escaped nets: {}; return vias: {}; optimized segments: {}; rounded corners: {}; parallel candidates: {}; workers: {}; fallbacks: {}; expanded states: {}; passes: {}",
                report.preserved.len(),
                report.routed.len(),
                report.rerouted.len(),
                report.unrouted.len(),
                report.ripup_events,
                report.shove_events,
                report.escaped_nets,
                report.generated_return_vias,
                report.optimized_segments,
                report.rounded_corners,
                report.parallel_candidates,
                report.parallel_workers,
                report.parallel_fallbacks,
                report.expanded_states,
                report.reroute_passes
            );
            if !allow_unrouted && !report.unrouted.is_empty() {
                bail!("unrouted nets: {}", report.unrouted.join(", "))
            }
            ensure_clean(&board)?;
            if drc {
                run_kicad_drc(&output)?;
            }
        }
        Command::RouteKicadCandidates {
            input,
            project,
            rules_file,
            output_dir,
            grid_mm,
            width_mm,
            clearance_mm,
            via_diameter_mm,
            via_drill_mm,
            bend_cost,
            via_cost,
            fab,
            fab_profile,
            policy_pack,
            candidates,
            workers,
            router_workers,
            allow_unrouted,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let rules = Rules {
                grid_nm: to_nm(grid_mm, "grid")?,
                track_width_nm: to_nm(width_mm, "track width")?,
                clearance_nm: to_nm(clearance_mm, "clearance")?,
                via_diameter_nm: to_nm(via_diameter_mm, "via diameter")?,
                via_drill_nm: to_nm(via_drill_mm, "via drill")?,
                bend_cost,
                via_cost,
            };
            if rules.via_drill_nm >= rules.via_diameter_nm {
                bail!("via drill must be smaller than via diameter");
            }
            let mut imported = import_kicad(&source, rules).map_err(anyhow::Error::msg)?;
            let project = project.or_else(|| {
                let candidate = input.with_extension("kicad_pro");
                candidate.exists().then_some(candidate)
            });
            if let Some(path) = project {
                let project_source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                apply_project_net_settings(&mut imported.board, &project_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("importing rules from {}", path.display()))?;
            }
            let rules_file = rules_file.or_else(|| {
                let candidate = input.with_extension("kicad_dru");
                candidate.exists().then_some(candidate)
            });
            if let Some(path) = rules_file {
                let rules_source = fs::read_to_string(&path)
                    .with_context(|| format!("reading {}", path.display()))?;
                apply_custom_design_rules(&mut imported.board, &rules_source)
                    .map_err(anyhow::Error::msg)
                    .with_context(|| format!("importing custom rules from {}", path.display()))?;
            }
            let profile = if let Some(path) = policy_pack {
                Some(load_policy_pack(&path)?.0.dfm_profile)
            } else {
                resolve_dfm_profile(fab.as_deref(), fab_profile.as_deref())?.0
            };
            if let Some(profile) = profile {
                apply_dfm_profile(&mut imported.board, &profile);
            }
            let results = route_candidates(
                &imported.board,
                &RoutingCandidateOptions {
                    candidates,
                    workers,
                    router_workers,
                },
            )
            .map_err(anyhow::Error::msg)?;
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            for candidate in &results.candidates {
                let path = output_dir.join(format!(
                    "{}-{}.kicad_pcb",
                    candidate.id,
                    routing_candidate_objective_name(candidate.objective)
                ));
                fs::write(
                    &path,
                    imported
                        .write_routes(&candidate.board.routes)
                        .map_err(anyhow::Error::msg)?,
                )
                .with_context(|| format!("writing {}", path.display()))?;
            }
            fs::write(
                output_dir.join("selected.kicad_pcb"),
                imported
                    .write_routes(&results.selected().board.routes)
                    .map_err(anyhow::Error::msg)?,
            )?;
            write_routing_candidate_reports(&output_dir, &results)?;
            eprintln!(
                "generated {} KiCad routing candidates ({} unique); Pareto front: {}; selected: {}",
                results.candidates.len(),
                results
                    .candidates
                    .iter()
                    .filter(|candidate| candidate.duplicate_of.is_none())
                    .count(),
                results.pareto_front.len(),
                results.selected_candidate_id
            );
            if !allow_unrouted && results.selected().quality.unrouted_nets != 0 {
                bail!(
                    "selected routing candidate has {} unrouted net(s)",
                    results.selected().quality.unrouted_nets
                )
            }
            ensure_clean(&results.selected().board)?;
        }
        Command::Check { input } => {
            let b = read(&input)?;
            if b.width_nm <= 0 || b.height_nm <= 0 || b.rules.grid_nm <= 0 {
                bail!("invalid board dimensions or grid")
            }
            for n in &b.nets {
                if n.terminals.len() < 2 {
                    bail!("net {} has fewer than two terminals", n.name)
                }
            }
            ensure_clean(&b)?;
            println!(
                "ok: {} nets, {} obstacles, {} routes",
                b.nets.len(),
                b.obstacles.len(),
                b.routes.len()
            );
        }
        Command::Dfm {
            input,
            fab,
            fab_profile,
            policy_pack,
            output,
            format,
        } => {
            let mut board = read(&input)?;
            let profile = if let Some(path) = policy_pack {
                Some(load_policy_pack(&path)?.0.dfm_profile)
            } else {
                resolve_dfm_profile(fab.as_deref(), fab_profile.as_deref())?.0
            };
            if let Some(profile) = profile {
                apply_dfm_profile(&mut board, &profile);
            }
            if board.manufacturing_rules.is_none() {
                bail!(
                    "board does not define manufacturing_rules; select --fab PROFILE, --fab-profile PATH, or --policy-pack PATH"
                )
            }
            let report = check_manufacturability(&board);
            let json = match format {
                ReportFormat::Json => serde_json::to_string_pretty(&report)?,
                ReportFormat::Sarif => {
                    serde_json::to_string_pretty(&check_report_to_sarif(&report))?
                }
            };
            if let Some(path) = output {
                fs::write(path, &json)?;
            } else {
                println!("{json}");
            }
            if !report.is_clean() {
                bail!("{} manufacturing violations", report.violations.len())
            }
        }
        Command::ImpedanceWidth {
            input,
            layer,
            target_ohms,
            differential_gap_mm,
            minimum_width_mm,
            maximum_width_mm,
        } => {
            if !target_ohms.is_finite() || target_ohms <= 0.0 {
                bail!("target impedance must be a positive finite value")
            }
            let board = read(&input)?;
            let stackup = board
                .stackup
                .iter()
                .find(|entry| entry.layer.name() == layer)
                .with_context(|| format!("no stackup entry for layer {layer}"))?;
            let minimum = to_nm(minimum_width_mm, "minimum width")?;
            let maximum = to_nm(maximum_width_mm, "maximum width")?;
            if maximum < minimum {
                bail!("maximum width must be at least minimum width")
            }
            let (width, estimated, mode) = if let Some(gap_mm) = differential_gap_mm {
                let gap = to_nm(gap_mm, "differential gap")?;
                let width = solve_stackup_differential_width_nm(
                    target_ohms,
                    gap,
                    stackup,
                    minimum,
                    maximum,
                )
                .context("target impedance is unreachable within the width range")?;
                let estimated =
                    pcbex_core::estimated_stackup_differential_impedance_ohms(width, gap, stackup)
                        .context("solved differential geometry is invalid")?;
                (width, estimated, "differential")
            } else {
                let width = solve_stackup_width_nm(target_ohms, stackup, minimum, maximum)
                    .context("target impedance is unreachable within the width range")?;
                let estimated = pcbex_core::estimated_stackup_impedance_ohms(width, stackup)
                    .context("solved single-ended geometry is invalid")?;
                (width, estimated, "single_ended")
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "mode": mode,
                    "layer": layer,
                    "target_ohms": target_ohms,
                    "estimated_ohms": estimated,
                    "width_nm": width,
                    "width_mm": width as f64 / 1_000_000.0
                }))?
            );
        }
        Command::ImpedanceReport {
            input,
            output,
            baseline,
            fail_on_violations,
        } => {
            let result = impedance_report(&read(&input)?);
            let regressions = baseline
                .map(|path| -> Result<Vec<String>> {
                    let baseline: pcbex_core::ImpedanceReport = serde_json::from_str(
                        &fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    )
                    .with_context(|| format!("parsing {}", path.display()))?;
                    Ok(result.regressions_against(&baseline))
                })
                .transpose()?
                .unwrap_or_default();
            let report = serde_json::to_string_pretty(&result)?;
            if let Some(path) = output {
                fs::write(path, report)?;
            } else {
                println!("{report}");
            }
            if fail_on_violations && !result.is_clean() {
                bail!(
                    "impedance quality failed: {} invalid geometries, {} out-of-tolerance segments, {} excessive transitions",
                    result.invalid_geometry_count,
                    result.out_of_tolerance_segment_count,
                    result.excessive_transition_count
                )
            }
            if !regressions.is_empty() {
                bail!("impedance regressions: {}", regressions.join("; "))
            }
        }
        Command::Render { input, output } => fs::write(output, render_svg(&read(&input)?))?,
        Command::Place {
            input,
            output,
            iterations,
            seed,
        } => {
            let problem: PlacementProblem = serde_json::from_str(
                &fs::read_to_string(&input)
                    .with_context(|| format!("reading {}", input.display()))?,
            )
            .with_context(|| format!("parsing {}", input.display()))?;
            let mut options = PlacementOptions::default();
            if let Some(value) = iterations {
                options.iterations = value;
            }
            if let Some(value) = seed {
                options.seed = value;
            }
            let result = place(&problem, &options).map_err(anyhow::Error::msg)?;
            fs::write(&output, serde_json::to_string_pretty(&result)?)
                .with_context(|| format!("writing {}", output.display()))?;
            eprintln!(
                "placement score: {:.3} -> {:.3}; accepted moves: {}",
                result.initial_score.total, result.final_score.total, result.accepted_moves
            );
        }
        Command::PlaceCandidates {
            input,
            output_dir,
            candidates,
            workers,
            iterations,
            seed,
        } => {
            let problem: PlacementProblem = serde_json::from_str(
                &fs::read_to_string(&input)
                    .with_context(|| format!("reading {}", input.display()))?,
            )
            .with_context(|| format!("parsing {}", input.display()))?;
            let options = placement_candidate_options(candidates, workers, iterations, seed);
            let results = place_candidates(&problem, &options).map_err(anyhow::Error::msg)?;
            write_candidate_reports(&output_dir, &results)?;
            eprintln!(
                "generated {} placement candidates; Pareto front: {}; selected: {}",
                results.candidates.len(),
                results.pareto_front.len(),
                results.selected_candidate_id
            );
        }
        Command::PlaceKicad {
            input,
            output,
            grid_mm,
            iterations,
            seed,
            json_output,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let imported = import_kicad(
                &source,
                Rules {
                    grid_nm: 250_000,
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    bend_cost: 5,
                    via_cost: 20,
                },
            )
            .map_err(anyhow::Error::msg)?;
            let problem = imported
                .placement_problem(to_nm(grid_mm, "placement grid")?)
                .map_err(anyhow::Error::msg)?;
            let mut options = PlacementOptions::default();
            if let Some(value) = iterations {
                options.iterations = value;
            }
            if let Some(value) = seed {
                options.seed = value;
            }
            let result = place(&problem, &options).map_err(anyhow::Error::msg)?;
            let placed = imported
                .write_placements(&result.components)
                .map_err(anyhow::Error::msg)?;
            fs::write(&output, placed).with_context(|| format!("writing {}", output.display()))?;
            if let Some(path) = json_output {
                fs::write(&path, serde_json::to_string_pretty(&result)?)
                    .with_context(|| format!("writing {}", path.display()))?;
            }
            eprintln!(
                "placement score: {:.3} -> {:.3}; accepted moves: {}",
                result.initial_score.total, result.final_score.total, result.accepted_moves
            );
        }
        Command::PlaceKicadCandidates {
            input,
            output_dir,
            grid_mm,
            candidates,
            workers,
            iterations,
            seed,
        } => {
            let source = fs::read_to_string(&input)
                .with_context(|| format!("reading {}", input.display()))?;
            let imported = import_kicad(
                &source,
                Rules {
                    grid_nm: 250_000,
                    track_width_nm: 250_000,
                    clearance_nm: 200_000,
                    via_diameter_nm: 600_000,
                    via_drill_nm: 300_000,
                    bend_cost: 5,
                    via_cost: 20,
                },
            )
            .map_err(anyhow::Error::msg)?;
            let problem = imported
                .placement_problem(to_nm(grid_mm, "placement grid")?)
                .map_err(anyhow::Error::msg)?;
            let options = placement_candidate_options(candidates, workers, iterations, seed);
            let results = place_candidates(&problem, &options).map_err(anyhow::Error::msg)?;
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            for candidate in &results.candidates {
                let board = imported
                    .write_placements(&candidate.result.components)
                    .map_err(anyhow::Error::msg)?;
                let path = output_dir.join(format!(
                    "{}-{}.kicad_pcb",
                    candidate.id,
                    candidate_objective_name(candidate.objective)
                ));
                fs::write(&path, board).with_context(|| format!("writing {}", path.display()))?;
            }
            let selected_board = imported
                .write_placements(&results.selected().result.components)
                .map_err(anyhow::Error::msg)?;
            fs::write(output_dir.join("selected.kicad_pcb"), selected_board)?;
            write_candidate_reports(&output_dir, &results)?;
            eprintln!(
                "generated {} KiCad placement candidates; Pareto front: {}; selected: {}",
                results.candidates.len(),
                results.pareto_front.len(),
                results.selected_candidate_id
            );
        }
        Command::Fabricate { input, output_dir } => {
            run_kicad_drc(&input)?;
            fs::create_dir_all(&output_dir)
                .with_context(|| format!("creating {}", output_dir.display()))?;
            run_kicad_export(
                &[
                    "pcb",
                    "export",
                    "gerbers",
                    "--layers",
                    "F.Cu,B.Cu,F.Mask,B.Mask,F.Silkscreen,B.Silkscreen,Edge.Cuts",
                    "--output",
                ],
                &output_dir,
                &input,
            )?;
            run_kicad_export(&["pcb", "export", "drill", "--output"], &output_dir, &input)?;
            eprintln!("manufacturing files written to {}", output_dir.display());
        }
    }
    Ok(())
}

fn placement_candidate_options(
    candidates: usize,
    workers: usize,
    iterations: Option<usize>,
    seed: Option<u64>,
) -> PlacementCandidateOptions {
    let mut placement = PlacementOptions::default();
    if let Some(iterations) = iterations {
        placement.iterations = iterations;
    }
    if let Some(seed) = seed {
        placement.seed = seed;
    }
    PlacementCandidateOptions {
        candidates,
        workers,
        placement,
    }
}

fn write_routing_candidate_reports(output_dir: &Path, results: &RoutingCandidateSet) -> Result<()> {
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    let manifest = output_dir.join("candidates.json");
    fs::write(&manifest, serde_json::to_string_pretty(results)?)
        .with_context(|| format!("writing {}", manifest.display()))?;
    for candidate in &results.candidates {
        let objective = routing_candidate_objective_name(candidate.objective);
        let board_path = output_dir.join(format!("{}-{objective}.board.json", candidate.id));
        fs::write(&board_path, serde_json::to_string_pretty(&candidate.board)?)
            .with_context(|| format!("writing {}", board_path.display()))?;
        let report_path = output_dir.join(format!("{}.report.json", candidate.id));
        fs::write(&report_path, serde_json::to_string_pretty(candidate)?)
            .with_context(|| format!("writing {}", report_path.display()))?;
    }
    let selected_board = output_dir.join("selected.board.json");
    fs::write(
        &selected_board,
        serde_json::to_string_pretty(&results.selected().board)?,
    )
    .with_context(|| format!("writing {}", selected_board.display()))?;
    let selected_report = output_dir.join("selected.report.json");
    fs::write(
        &selected_report,
        serde_json::to_string_pretty(results.selected())?,
    )
    .with_context(|| format!("writing {}", selected_report.display()))?;
    Ok(())
}

fn routing_candidate_objective_name(objective: RoutingCandidateObjective) -> &'static str {
    match objective {
        RoutingCandidateObjective::Balanced => "balanced",
        RoutingCandidateObjective::Shortest => "shortest",
        RoutingCandidateObjective::ViaMinimized => "via-minimized",
        RoutingCandidateObjective::BendMinimized => "bend-minimized",
        RoutingCandidateObjective::AlternateOrder => "alternate-order",
    }
}

fn write_candidate_reports(output_dir: &Path, results: &PlacementCandidateSet) -> Result<()> {
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    let manifest = output_dir.join("candidates.json");
    fs::write(&manifest, serde_json::to_string_pretty(results)?)
        .with_context(|| format!("writing {}", manifest.display()))?;
    for candidate in &results.candidates {
        let path = output_dir.join(format!("{}.json", candidate.id));
        fs::write(&path, serde_json::to_string_pretty(candidate)?)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    let selected = output_dir.join("selected.json");
    fs::write(&selected, serde_json::to_string_pretty(results.selected())?)
        .with_context(|| format!("writing {}", selected.display()))?;
    Ok(())
}

fn candidate_objective_name(objective: CandidateObjective) -> &'static str {
    match objective {
        CandidateObjective::Balanced => "balanced",
        CandidateObjective::Wirelength => "wirelength",
        CandidateObjective::Routability => "routability",
        CandidateObjective::Constraints => "constraints",
        CandidateObjective::Legalization => "legalization",
    }
}

fn input_descriptor(path: &Path, bytes: &[u8]) -> InputDescriptor {
    InputDescriptor {
        path: path.display().to_string(),
        bytes: bytes.len(),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    }
}

fn write_or_print_json(value: &serde_json::Value, output: Option<&PathBuf>) -> Result<()> {
    let document = serde_json::to_string_pretty(value)?;
    if let Some(path) = output {
        fs::write(path, document).with_context(|| format!("writing {}", path.display()))?;
    } else {
        println!("{document}");
    }
    Ok(())
}

fn parse_ai_requirement(value: &str) -> Result<AiRequirement> {
    let (id, text) = value
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("AI requirement must use id=text syntax"))?;
    if id.trim().is_empty() || text.trim().is_empty() {
        bail!("AI requirement id and text must not be blank");
    }
    Ok(AiRequirement {
        id: id.trim().into(),
        text: text.trim().into(),
    })
}

fn write_new_file(path: &Path, contents: &str, private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

fn write_new_file_set(files: &[(&Path, &str)]) -> Result<()> {
    let mut created = Vec::with_capacity(files.len());
    for (path, contents) in files {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = match options.open(path) {
            Ok(file) => file,
            Err(error) => {
                for created_path in created {
                    let _ = fs::remove_file(created_path);
                }
                return Err(error).with_context(|| format!("creating {}", path.display()));
            }
        };
        created.push(*path);
        if let Err(error) = file.write_all(contents.as_bytes()) {
            for created_path in created {
                let _ = fs::remove_file(created_path);
            }
            return Err(error).with_context(|| format!("writing {}", path.display()));
        }
    }
    Ok(())
}

fn read_secret_key(path: &Path) -> Result<[u8; 32]> {
    read_hex_key(path, "approval private key")
}

fn random_secret_key() -> Result<[u8; 32]> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| anyhow::anyhow!("generating Ed25519 key: {error}"))?;
    Ok(secret)
}

fn current_unix_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs())
}

fn read_hex_key(path: &Path, description: &str) -> Result<[u8; 32]> {
    let value = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    decode_hex_key(value.trim(), description)
}

fn decode_hex_key(value: &str, description: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        bail!("{description} must contain 64 lowercase hexadecimal digits");
    }
    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("decoding {description}"))?;
    }
    Ok(secret)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn simulation_artifact(path: &Path) -> Result<SimulationArtifact> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("simulation artifact requires a UTF-8 basename"))?
        .to_string();
    let mut file = fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("simulation artifact size overflow"))?;
        digest.update(&buffer[..count]);
    }
    let media_type = match path.extension().and_then(|extension| extension.to_str()) {
        Some("csv") => "text/csv",
        Some("json") => "application/json",
        Some("txt" | "log") => "text/plain",
        _ => "application/octet-stream",
    };
    Ok(SimulationArtifact {
        name,
        media_type: media_type.into(),
        bytes,
        sha256: format!("{:x}", digest.finalize()),
    })
}

fn manufacturing_evidence_descriptor(path: &Path) -> Result<EvidenceDescriptor> {
    let name = portable_basename(path)?;
    let mut file = fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .with_context(|| format!("reading {}", path.display()))?;
        if count == 0 {
            break;
        }
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| anyhow::anyhow!("manufacturing evidence artifact size overflow"))?;
        digest.update(&buffer[..count]);
    }
    Ok(EvidenceDescriptor {
        name,
        bytes,
        sha256: format!("{:x}", digest.finalize()),
    })
}

fn portable_basename(path: &Path) -> Result<String> {
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{} has no portable UTF-8 basename", path.display()))
}

fn require_distinct_outputs<'a>(
    paths: impl IntoIterator<Item = Option<&'a Path>>,
    label: &str,
) -> Result<()> {
    let paths = paths.into_iter().flatten().collect::<Vec<_>>();
    for (index, path) in paths.iter().enumerate() {
        if paths[index + 1..].contains(path) {
            bail!("{label} output paths must be distinct");
        }
    }
    Ok(())
}

fn read_described_json<T: DeserializeOwned>(path: &Path) -> Result<(T, InputDescriptor)> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok((value, input_descriptor(path, &bytes)))
}

fn approval_event_descriptor(
    kind: ApprovalArtifactKindArg,
    path: &Path,
) -> Result<ApprovalEventDescriptor> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading approval artifact {}", path.display()))?;
    let parse_error = |error: serde_json::Error| {
        anyhow::anyhow!("invalid approval artifact {}: {error}", path.display())
    };
    match kind {
        ApprovalArtifactKindArg::SignedAiApproval => {
            let artifact: SignedAiApproval = serde_json::from_str(&source).map_err(parse_error)?;
            Ok(ApprovalEventDescriptor {
                artifact_kind: ApprovalArtifactKind::SignedAiApproval,
                artifact_sha256: normalized_json_sha256(&artifact)?,
                subject_id: artifact.request_sha256.clone(),
                request_sha256: Some(artifact.request_sha256),
                session_sha256: artifact.session_sha256,
                signer_id: Some(artifact.signer_id),
                outcome: if artifact.approved {
                    "approved".into()
                } else {
                    "rejected".into()
                },
            })
        }
        ApprovalArtifactKindArg::AiQuorumReport => {
            let artifact: AiQuorumArtifact = serde_json::from_str(&source).map_err(parse_error)?;
            let (request_sha256, session_sha256, approved) = match &artifact {
                AiQuorumArtifact::SessionRouted(report) => (
                    report.session.request_sha256.clone(),
                    Some(report.session.session_sha256.clone()),
                    report.routed_quorum.routed_quorum_met,
                ),
                AiQuorumArtifact::Session(report) => (
                    report.request_sha256.clone(),
                    Some(report.session_sha256.clone()),
                    report.quorum.quorum_met,
                ),
                AiQuorumArtifact::Routed(report) => (
                    report.quorum.request_sha256.clone(),
                    None,
                    report.routed_quorum_met,
                ),
                AiQuorumArtifact::Global(report) => {
                    (report.request_sha256.clone(), None, report.quorum_met)
                }
            };
            Ok(ApprovalEventDescriptor {
                artifact_kind: ApprovalArtifactKind::AiQuorumReport,
                artifact_sha256: normalized_json_sha256(&artifact)?,
                subject_id: request_sha256.clone(),
                request_sha256: Some(request_sha256),
                session_sha256,
                signer_id: None,
                outcome: if approved {
                    "approved".into()
                } else {
                    "quorum_not_met".into()
                },
            })
        }
        ApprovalArtifactKindArg::SignedHumanEscalation => {
            let artifact: SignedHumanEscalation =
                serde_json::from_str(&source).map_err(parse_error)?;
            let outcome = match artifact.decision {
                HumanEscalationDecision::Approve => "approved",
                HumanEscalationDecision::Reject => "rejected",
            };
            Ok(ApprovalEventDescriptor {
                artifact_kind: ApprovalArtifactKind::SignedHumanEscalation,
                artifact_sha256: normalized_json_sha256(&artifact)?,
                subject_id: artifact.request_sha256.clone(),
                request_sha256: Some(artifact.request_sha256),
                session_sha256: Some(artifact.session_sha256),
                signer_id: Some(artifact.signer_id),
                outcome: outcome.into(),
            })
        }
        ApprovalArtifactKindArg::HumanEscalationReport => {
            let artifact: HumanEscalationReport =
                serde_json::from_str(&source).map_err(parse_error)?;
            Ok(ApprovalEventDescriptor {
                artifact_kind: ApprovalArtifactKind::HumanEscalationReport,
                artifact_sha256: normalized_json_sha256(&artifact)?,
                subject_id: artifact.request_sha256.clone(),
                request_sha256: Some(artifact.request_sha256),
                session_sha256: Some(artifact.session_sha256),
                signer_id: None,
                outcome: if artifact.escalation_approved {
                    "approved".into()
                } else {
                    "not_approved".into()
                },
            })
        }
        ApprovalArtifactKindArg::SignedPolicyPack => {
            let artifact = parse_signed_policy_pack(&source).map_err(anyhow::Error::msg)?;
            Ok(ApprovalEventDescriptor {
                artifact_kind: ApprovalArtifactKind::SignedPolicyPack,
                artifact_sha256: normalized_json_sha256(&artifact)?,
                subject_id: format!(
                    "{}@{}",
                    artifact.policy_pack.id, artifact.policy_pack.revision
                ),
                request_sha256: None,
                session_sha256: None,
                signer_id: Some(artifact.signer_id),
                outcome: "published".into(),
            })
        }
    }
}

fn normalized_json_sha256(value: &impl Serialize) -> Result<String> {
    Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(value)?)))
}

fn render_comparison_summary(delta: &AnalysisDelta) -> String {
    let length_percent = delta
        .changes
        .total_length_percent
        .map_or_else(|| "n/a".to_string(), |value| format!("{value:+.2}%"));
    let mut summary = format!(
        "# pcbex analysis comparison\n\n\
         **Status:** {}\n\n\
         | Metric | Baseline | Current | Change |\n\
         |---|---:|---:|---:|\n\
         | Total route length (nm) | {} | {} | {:+} ({}) |\n\
         | Vias | {} | {} | {:+} |\n\
         | Bends | {} | {} | {:+} |\n\
         | Routed nets | {} | {} | {:+} |\n\
         | Unrouted nets | {} | {} | {:+} |\n\
         | Violations | {} | {} | {:+} |\n",
        if delta.is_regression() {
            "regressions found"
        } else {
            "no regressions"
        },
        delta.baseline.total_length_nm,
        delta.current.total_length_nm,
        delta.changes.total_length_nm,
        length_percent,
        delta.baseline.total_vias,
        delta.current.total_vias,
        delta.changes.total_vias,
        delta.baseline.total_bends,
        delta.current.total_bends,
        delta.changes.total_bends,
        delta.baseline.routed_nets,
        delta.current.routed_nets,
        delta.changes.routed_nets,
        delta.baseline.unrouted_nets,
        delta.current.unrouted_nets,
        delta.changes.unrouted_nets,
        delta.baseline.violations,
        delta.current.violations,
        delta.changes.violations,
    );
    if !delta.quality_regressions.is_empty() {
        summary.push_str("\n## Quality regressions\n\n");
        for regression in &delta.quality_regressions {
            summary.push_str(&format!("- {}\n", regression.replace(['\r', '\n'], " ")));
        }
    }
    append_violation_delta(&mut summary, "New violations", &delta.new_violations);
    append_violation_delta(
        &mut summary,
        "Resolved violations",
        &delta.resolved_violations,
    );
    summary
}

fn append_violation_delta(
    summary: &mut String,
    heading: &str,
    violations: &[pcbex_core::analysis::ViolationFingerprint],
) {
    if violations.is_empty() {
        return;
    }
    summary.push_str(&format!("\n## {heading}\n\n"));
    for violation in violations {
        summary.push_str(&format!(
            "- `{}`: {} (nets: {})\n",
            violation.rule,
            violation.message.replace(['\r', '\n'], " "),
            violation
                .net_ids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
}

fn render_analysis_summary(
    quality: &RoutingQuality,
    report: &pcbex_core::checking::CheckReport,
) -> String {
    let mut summary = format!(
        "# pcbex KiCad analysis\n\n\
         **Status:** {}\n\n\
         | Metric | Value |\n\
         |---|---:|\n\
         | Internal DRC/DFM violations | {} |\n\
         | Routed nets | {} |\n\
         | Unrouted nets | {} |\n\
         | Total route length (nm) | {} |\n\
         | Vias | {} |\n\
         | Bends | {} |\n",
        if report.is_clean() {
            "clean"
        } else {
            "violations found"
        },
        report.violations.len(),
        quality.routed_nets,
        quality.unrouted_nets,
        quality.total_length_nm,
        quality.total_vias,
        quality.total_bends,
    );
    if !report.violations.is_empty() {
        summary.push_str("\n## Violations\n\n");
        for violation in &report.violations {
            summary.push_str(&format!(
                "- `{}`: {}\n",
                violation.rule,
                violation.message.replace(['\r', '\n'], " ")
            ));
        }
    }
    summary
}

fn to_nm(mm: f64, name: &str) -> Result<i64> {
    if !mm.is_finite() || mm <= 0.0 {
        bail!("{name} must be a positive finite value")
    }
    Ok((mm * 1_000_000.0).round() as i64)
}

fn run_kicad_drc(board: &PathBuf) -> Result<()> {
    let report = board.with_extension("drc.rpt");
    let temp = std::env::temp_dir();
    let status = ProcessCommand::new("kicad-cli")
        .args(["pcb", "drc", "--exit-code-violations", "--output"])
        .arg(&report)
        .arg(board)
        .env("XDG_CONFIG_HOME", temp.join("pcbex-kicad-config"))
        .env("XDG_CACHE_HOME", temp.join("pcbex-kicad-cache"))
        .env("XDG_DATA_HOME", temp.join("pcbex-kicad-data"))
        .status()
        .context("running kicad-cli; install KiCad or omit --drc")?;
    if !status.success() {
        bail!(
            "KiCad DRC failed (status {status}); report: {}",
            report.display()
        )
    }
    eprintln!("KiCad DRC passed; report: {}", report.display());
    Ok(())
}

fn run_kicad_export(arguments: &[&str], output: &PathBuf, board: &PathBuf) -> Result<()> {
    let temp = std::env::temp_dir();
    let status = ProcessCommand::new("kicad-cli")
        .args(arguments)
        .arg(output)
        .arg(board)
        .env("XDG_CONFIG_HOME", temp.join("pcbex-kicad-config"))
        .env("XDG_CACHE_HOME", temp.join("pcbex-kicad-cache"))
        .env("XDG_DATA_HOME", temp.join("pcbex-kicad-data"))
        .status()
        .context("running kicad-cli manufacturing export")?;
    if !status.success() {
        bail!("KiCad manufacturing export failed with status {status}")
    }
    Ok(())
}

fn ensure_clean(board: &Board) -> Result<()> {
    let report = check_board(board);
    if report.is_clean() {
        return Ok(());
    }
    let summary = report
        .violations
        .iter()
        .take(8)
        .map(|v| format!("[{}] {}", v.rule, v.message))
        .collect::<Vec<_>>()
        .join("; ");
    bail!(
        "internal rule check found {} violation(s): {}",
        report.violations.len(),
        summary
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cli(arguments: &[&str]) -> std::result::Result<Cli, clap::Error> {
        let arguments = arguments
            .iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>();
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(move || Cli::try_parse_from(arguments))
            .expect("CLI parser test thread starts")
            .join()
            .expect("CLI parser test thread succeeds")
    }

    #[test]
    fn generates_completions_for_every_supported_shell() {
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                for shell in [
                    Shell::Bash,
                    Shell::Elvish,
                    Shell::Fish,
                    Shell::PowerShell,
                    Shell::Zsh,
                ] {
                    let mut command = Cli::command();
                    let name = command.get_name().to_string();
                    let mut output = Vec::new();
                    generate(shell, &mut command, name, &mut output);
                    let output =
                        String::from_utf8(output).expect("completion output must be UTF-8");
                    assert!(output.contains("pcbex"));
                    assert!(output.contains("completion"));
                }
            })
            .expect("completion test thread starts")
            .join()
            .expect("completion generation succeeds");
    }

    #[test]
    fn parses_impedance_width_solver_arguments() {
        let cli = parse_cli(&[
            "pcbex",
            "impedance-width",
            "board.json",
            "--layer",
            "In1.Cu",
            "--target-ohms",
            "90",
            "--differential-gap-mm",
            "0.15",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::ImpedanceWidth {
                layer,
                target_ohms: 90.0,
                differential_gap_mm: Some(0.15),
                ..
            } if layer == "In1.Cu"
        ));
    }

    #[test]
    fn parses_impedance_report_output() {
        let cli = parse_cli(&[
            "pcbex",
            "impedance-report",
            "board.json",
            "--output",
            "report.json",
            "--baseline",
            "baseline.json",
            "--fail-on-violations",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::ImpedanceReport {
                input,
                output: Some(output),
                baseline: Some(baseline),
                fail_on_violations: true
            } if input.as_os_str() == "board.json"
                && output.as_os_str() == "report.json"
                && baseline.as_os_str() == "baseline.json"
        ));
    }

    #[test]
    fn parses_placement_candidate_controls() {
        let cli = parse_cli(&[
            "pcbex",
            "place-kicad-candidates",
            "board.kicad_pcb",
            "--output-dir",
            "placements",
            "--candidates",
            "9",
            "--workers",
            "3",
            "--iterations",
            "1200",
            "--seed",
            "42",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::PlaceKicadCandidates {
                candidates: 9,
                workers: 3,
                iterations: Some(1200),
                seed: Some(42),
                ..
            }
        ));
    }

    #[test]
    fn parses_routing_candidate_controls() {
        let cli = parse_cli(&[
            "pcbex",
            "route-kicad-candidates",
            "board.kicad_pcb",
            "--output-dir",
            "routes",
            "--candidates",
            "10",
            "--workers",
            "4",
            "--router-workers",
            "2",
            "--fab",
            "jlcpcb-2layer",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::RouteKicadCandidates {
                candidates: 10,
                workers: 4,
                router_workers: 2,
                fab: Some(fab),
                ..
            } if fab == "jlcpcb-2layer"
        ));
    }

    #[test]
    fn parses_schematic_import_coverage_gate() {
        let cli = parse_cli(&[
            "pcbex",
            "import-schematic",
            "design.kicad_sch",
            "--output",
            "design.schematic.json",
            "--require-complete",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::ImportSchematic {
                input,
                output,
                require_complete: true,
            } if input.as_os_str() == "design.kicad_sch"
                && output.as_os_str() == "design.schematic.json"
        ));
    }

    #[test]
    fn parses_analyze_kicad_artifact_options() {
        let cli = parse_cli(&[
            "pcbex",
            "analyze-kicad",
            "board.kicad_pcb",
            "--output-dir",
            "analysis",
            "--project",
            "board.kicad_pro",
            "--rules-file",
            "board.kicad_dru",
            "--fab",
            "jlcpcb-2layer",
            "--fail-on-violations",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::AnalyzeKicad {
                input,
                project: Some(project),
                rules_file: Some(rules_file),
                output_dir,
                fab: Some(fab),
                fail_on_violations: true,
                ..
            } if input.as_os_str() == "board.kicad_pcb"
                && project.as_os_str() == "board.kicad_pro"
                && rules_file.as_os_str() == "board.kicad_dru"
                && fab == "jlcpcb-2layer"
                && output_dir.as_os_str() == "analysis"
        ));
    }

    #[test]
    fn resolves_fabrication_profile_aliases_with_versioned_identity() {
        let profile = resolve_dfm_profile(Some("pcbway-2layer"), None)
            .unwrap()
            .0
            .unwrap();
        assert_eq!(profile.id, "pcbway-standard-2layer-1oz-v1");
        assert!(resolve_dfm_profile(Some("missing-profile"), None).is_err());
    }

    #[test]
    fn parses_external_fabrication_profile_and_rejects_ambiguous_selection() {
        let cli = parse_cli(&[
            "pcbex",
            "analyze-kicad",
            "board.kicad_pcb",
            "--output-dir",
            "analysis",
            "--fab-profile",
            "acme-profile.json",
        ])
        .unwrap();
        assert!(matches!(
            *cli.command,
            Command::AnalyzeKicad {
                fab: None,
                fab_profile: Some(path),
                ..
            } if path.as_os_str() == "acme-profile.json"
        ));
        assert!(
            parse_cli(&[
                "pcbex",
                "dfm",
                "board.json",
                "--fab",
                "jlcpcb-2layer",
                "--fab-profile",
                "acme-profile.json",
            ])
            .is_err()
        );
    }

    #[test]
    fn input_descriptors_use_sha256() {
        let descriptor = input_descriptor(&PathBuf::from("board.kicad_pcb"), b"abc");
        assert_eq!(descriptor.bytes, 3);
        assert_eq!(
            descriptor.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn analysis_summary_reports_metrics_and_violations() {
        let quality = RoutingQuality {
            total_length_nm: 42,
            total_vias: 2,
            total_bends: 3,
            routed_nets: 1,
            unrouted_nets: 4,
            nets: vec![],
            differential_pairs: vec![],
        };
        let report = pcbex_core::checking::CheckReport {
            violations: vec![pcbex_core::checking::Violation {
                rule: "clearance".to_string(),
                message: "too close".to_string(),
                net_ids: vec![1],
            }],
        };

        let summary = render_analysis_summary(&quality, &report);
        assert!(summary.contains("violations found"));
        assert!(summary.contains("| Unrouted nets | 4 |"));
        assert!(summary.contains("- `clearance`: too close"));
    }

    #[test]
    fn parses_compare_analysis_regression_gate() {
        let cli = parse_cli(&[
            "pcbex",
            "compare-analysis",
            "baseline",
            "current",
            "--output-dir",
            "comparison",
            "--fail-on-regressions",
        ])
        .unwrap();

        assert!(matches!(
            *cli.command,
            Command::CompareAnalysis {
                baseline_dir,
                current_dir,
                output_dir,
                fail_on_regressions: true,
            } if baseline_dir.as_os_str() == "baseline"
                && current_dir.as_os_str() == "current"
                && output_dir.as_os_str() == "comparison"
        ));
    }
}
