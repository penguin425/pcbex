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
    AiRequirement, AiReviewRequest, AiReviewResponse, ElectricalPolicy, ElectricalReview,
    ElectricalWaiverSet, SignedAiApproval, SimulationArtifact, SimulationEvidence,
    ai_review_request_json_schema, ai_review_response_json_schema, apply_custom_design_rules,
    apply_electrical_waivers, apply_project_net_settings, approval_public_key,
    build_ai_review_request, check_schematic, compare_electrical_reviews,
    electrical_explanation_json_schema, electrical_policy_json_schema,
    electrical_review_comparison_json_schema, electrical_review_json_schema,
    electrical_review_to_junit, electrical_review_to_sarif, electrical_waiver_report_json_schema,
    electrical_waiver_set_json_schema, explain_electrical_review, import as import_kicad,
    import_schematic, parse_ai_review_response, parse_electrical_policy,
    parse_simulation_declaration, record_simulation_evidence, schematic_json_schema,
    sign_ai_review, signed_ai_approval_json_schema, simulation_declaration_json_schema,
    simulation_evidence_json_schema, verify_signed_ai_approval,
};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::Command as ProcessCommand,
};

mod mcp;
mod policy_pack;

use policy_pack::{
    OrganizationPolicyPack, SignedPolicyPack, parse_policy_pack, parse_signed_policy_pack,
    policy_pack_json_schema, sign_policy_pack, signed_policy_pack_json_schema,
    verify_signed_policy_pack,
};

#[derive(Parser)]
#[command(version, about = "Deterministic PCB physical-design engine")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ReportFormat {
    Json,
    Sarif,
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
    /// Normalize a KiCad schematic into the versioned electrical-design IR.
    ImportSchematic {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        /// Fail after writing the IR when buses or hierarchy prevent complete coverage.
        #[arg(long)]
        require_complete: bool,
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
        /// Also require the verified envelope to represent an approval.
        #[arg(long)]
        require_approved: bool,
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
        #[arg(short, long)]
        output: Option<PathBuf>,
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
    match cli.command {
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
        Command::PrepareAiReview {
            input,
            electrical_review,
            policy,
            simulation_evidence,
            requirements,
            policy_pack,
            allow_no_simulation,
            output,
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
            fs::write(&output, serde_json::to_string_pretty(&request)?)
                .with_context(|| format!("writing {}", output.display()))?;
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
            let approval = sign_ai_review(&request, &response, &signer_id, &secret)
                .map_err(anyhow::Error::msg)?;
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
            verify_signed_ai_approval(&approval, &request, &response, &public_key)
                .map_err(anyhow::Error::msg)?;
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
            output,
        } => {
            let signed = load_signed_policy_pack(&input)?;
            let public_key = read_hex_key(&public_key, "trusted policy public key")?;
            verify_signed_policy_pack(&signed, &public_key)
                .map_err(anyhow::Error::msg)
                .context("verifying signed organization policy pack")?;
            let normalized = format!("{}\n", serde_json::to_string_pretty(&signed.policy_pack)?);
            if let Some(path) = output {
                write_new_file(&path, &normalized, false)?;
            } else {
                print!("{normalized}");
            }
            eprintln!(
                "verified policy pack {} revision {} signed by {}",
                signed.policy_pack.id, signed.policy_pack.revision, signed.signer_id
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

fn read_secret_key(path: &Path) -> Result<[u8; 32]> {
    read_hex_key(path, "approval private key")
}

fn random_secret_key() -> Result<[u8; 32]> {
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret)
        .map_err(|error| anyhow::anyhow!("generating Ed25519 key: {error}"))?;
    Ok(secret)
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

fn read_described_json<T: DeserializeOwned>(path: &Path) -> Result<(T, InputDescriptor)> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let value =
        serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))?;
    Ok((value, input_descriptor(path, &bytes)))
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

    #[test]
    fn generates_completions_for_every_supported_shell() {
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
            let output = String::from_utf8(output).expect("completion output must be UTF-8");
            assert!(output.contains("pcbex"));
            assert!(output.contains("completion"));
        }
    }

    #[test]
    fn parses_impedance_width_solver_arguments() {
        let cli = Cli::try_parse_from([
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
            cli.command,
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
        let cli = Cli::try_parse_from([
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
            cli.command,
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
        let cli = Cli::try_parse_from([
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
            cli.command,
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
        let cli = Cli::try_parse_from([
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
            cli.command,
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
        let cli = Cli::try_parse_from([
            "pcbex",
            "import-schematic",
            "design.kicad_sch",
            "--output",
            "design.schematic.json",
            "--require-complete",
        ])
        .unwrap();

        assert!(matches!(
            cli.command,
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
        let cli = Cli::try_parse_from([
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
            cli.command,
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
        let cli = Cli::try_parse_from([
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
            cli.command,
            Command::AnalyzeKicad {
                fab: None,
                fab_profile: Some(path),
                ..
            } if path.as_os_str() == "acme-profile.json"
        ));
        assert!(
            Cli::try_parse_from([
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
        let cli = Cli::try_parse_from([
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
            cli.command,
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
