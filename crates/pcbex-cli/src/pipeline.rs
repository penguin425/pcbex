//! Final, fail-closed gate for the local hardware development pipeline.

use crate::factory::{
    FactorySubmissionReceipt, factory_feedback_passed, validate_factory_submission_receipt,
    validate_manufacturing_package,
};
use crate::firmware::{
    FIRMWARE_ARTIFACTS, FIRMWARE_SCHEMA_VERSION, FirmwareBuildEvidence, FirmwareCommandEvidence,
    FirmwareManifest, MAX_FIRMWARE_ARTIFACT_BYTES,
};
use crate::policy_pack::parse_policy_pack;
use pcbex_core::{
    DfmProfile, Rules, apply_dfm_profile, checking::CheckReport, checking::check_board,
    parse_external_dfm_profile, quality::RoutingQuality, quality::routing_quality,
    validate_dfm_profile,
};
use pcbex_kicad::{
    ElectricalPolicy, ElectricalReview, apply_custom_design_rules, apply_project_net_settings,
    check_schematic, import as import_kicad, import_schematic, parse_electrical_policy,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
};

const MAX_SCHEMATIC_BYTES: u64 = 64 * 1024 * 1024;
const MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REVIEW_BYTES: u64 = 64 * 1024 * 1024;
const MAX_BOARD_BYTES: u64 = 128 * 1024 * 1024;
const MAX_ANALYSIS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
// A receipt repeats normalized quote/findings beside the bounded raw response,
// and pretty JSON can be substantially larger than the provider's 8 MiB body.
const MAX_FACTORY_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIRMWARE_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FIRMWARE_TOTAL_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FINDINGS: usize = 100_000;
const MAX_NETS: usize = 100_000;
const MAX_VIOLATIONS: usize = 100_000;
const MAX_COMMAND_ARGUMENTS: usize = 256;
const MAX_TEXT_CHARS: usize = 4096;
const MAX_FAILURE_CHARS: usize = 4096;

const ANALYSIS_ARTIFACTS: [&str; 7] = [
    "board.json",
    "board.svg",
    "checks.json",
    "quality.json",
    "report.sarif",
    "summary.md",
    "run.json",
];

pub struct PipelineInputs<'a> {
    pub schematic: &'a Path,
    pub electrical_policy: Option<&'a Path>,
    pub electrical_review: &'a Path,
    pub board: &'a Path,
    pub analysis_manifest: &'a Path,
    pub analysis_checks: &'a Path,
    pub quality: &'a Path,
    pub analysis_project: Option<&'a Path>,
    pub analysis_rules: Option<&'a Path>,
    pub analysis_dfm_profile: Option<&'a Path>,
    pub analysis_policy_pack: Option<&'a Path>,
    pub manufacturing_package: &'a Path,
    pub firmware_manifest: &'a Path,
    pub factory_receipt: Option<&'a Path>,
    pub require_factory: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PipelineEvidence {
    pub role: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PipelinePhase {
    pub name: String,
    pub evidence: Vec<PipelineEvidence>,
    pub passed: bool,
    pub checks: Vec<String>,
    pub failures: Vec<String>,
}

impl PipelinePhase {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            evidence: Vec::new(),
            passed: false,
            checks: Vec::new(),
            failures: Vec::new(),
        }
    }

    fn fail(&mut self, message: impl Into<String>) {
        self.failures
            .push(bound_text(&message.into(), MAX_FAILURE_CHARS));
    }

    fn check(&mut self, message: impl Into<String>) {
        self.checks
            .push(bound_text(&message.into(), MAX_TEXT_CHARS));
    }

    fn finish(mut self) -> Self {
        self.passed = self.failures.is_empty();
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PipelineIdentities {
    pub schematic_sha256: Option<String>,
    pub board_sha256: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PipelineGateReport {
    pub schema_version: u32,
    pub pipeline: &'static str,
    pub identities: PipelineIdentities,
    pub phases: Vec<PipelinePhase>,
    pub passed: bool,
    pub failures: Vec<String>,
}

#[derive(Debug)]
struct Snapshot {
    bytes: Vec<u8>,
    evidence: PipelineEvidence,
}

#[derive(Clone, Debug)]
struct BoardIdentity {
    bytes: u64,
    sha256: String,
    file_name: Option<String>,
}

#[derive(Clone, Debug)]
struct ManufacturingIdentity {
    bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug)]
struct AnalysisBinding {
    result: AnalysisResult,
    recomputed_quality: RoutingQuality,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalysisDescriptor {
    path: String,
    bytes: u64,
    sha256: String,
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
struct AnalysisConfiguration {
    rules: StrictRules,
    project_settings_loaded: bool,
    applied_custom_rules: usize,
    dfm_profile: Option<DfmProfile>,
    organization_policy_pack: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
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
    input: AnalysisDescriptor,
    project: Option<AnalysisDescriptor>,
    rules_file: Option<AnalysisDescriptor>,
    dfm_profile_file: Option<AnalysisDescriptor>,
    policy_pack_file: Option<AnalysisDescriptor>,
    configuration: AnalysisConfiguration,
    result: AnalysisResult,
    artifacts: Vec<String>,
}

/// Validate every pipeline phase and retain all independent failures.
pub fn verify_pipeline(inputs: &PipelineInputs<'_>) -> PipelineGateReport {
    let (electrical, schematic_sha256) = electrical_phase(inputs);
    let (analysis, board_identity, analysis_binding) = analysis_phase(inputs);
    let quality = quality_phase(inputs, analysis_binding.as_ref());
    let (manufacturing, manufacturing_identity) =
        manufacturing_phase(inputs, board_identity.as_ref());
    let firmware = firmware_phase(inputs, schematic_sha256.as_deref());
    let factory_enabled = inputs.require_factory || inputs.factory_receipt.is_some();
    let mut phases = vec![electrical, analysis, quality, manufacturing, firmware];
    if factory_enabled {
        phases.push(factory_phase(
            inputs.factory_receipt,
            manufacturing_identity.as_ref(),
        ));
    }
    let failures = phases
        .iter()
        .flat_map(|phase| {
            phase
                .failures
                .iter()
                .map(|failure| bound_text(&format!("{}: {failure}", phase.name), MAX_FAILURE_CHARS))
        })
        .collect::<Vec<_>>();
    PipelineGateReport {
        schema_version: if factory_enabled { 2 } else { 1 },
        pipeline: if factory_enabled {
            "pcbex-hardware-v2"
        } else {
            "pcbex-hardware-v1"
        },
        identities: PipelineIdentities {
            schematic_sha256,
            board_sha256: board_identity.map(|identity| identity.sha256),
        },
        passed: failures.is_empty(),
        phases,
        failures,
    }
}

pub fn pipeline_gate_schema() -> Value {
    pipeline_gate_schema_for(false)
}

pub fn pipeline_factory_gate_schema() -> Value {
    pipeline_gate_schema_for(true)
}

fn pipeline_gate_schema_for(include_factory: bool) -> Value {
    let schema_version = if include_factory { 2 } else { 1 };
    let pipeline = if include_factory {
        "pcbex-hardware-v2"
    } else {
        "pcbex-hardware-v1"
    };
    let schema_id = if include_factory {
        "https://github.com/penguin425/pcbex/schema/pipeline-gate-v2.json"
    } else {
        "https://github.com/penguin425/pcbex/schema/pipeline-gate-v1.json"
    };
    let title = if include_factory {
        "pcbex factory-bound hardware pipeline gate"
    } else {
        "pcbex hash-bound hardware pipeline gate"
    };
    let mut phase_schemas = vec![
        phase_schema("electrical-erc"),
        phase_schema("analysis-drc"),
        phase_schema("routing-quality"),
        phase_schema("manufacturing-package"),
        phase_schema("firmware-build"),
    ];
    if include_factory {
        phase_schemas.push(phase_schema("factory-dfm"));
    }
    let phase_count = phase_schemas.len();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": schema_id,
        "title": title,
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "pipeline", "identities", "phases", "passed", "failures"
        ],
        "properties": {
            "schema_version": {"const": schema_version},
            "pipeline": {"const": pipeline},
            "identities": {"$ref": "#/$defs/identities"},
            "phases": {
                "type": "array",
                "minItems": phase_count,
                "maxItems": phase_count,
                "prefixItems": phase_schemas,
                "items": false
            },
            "passed": {"type": "boolean"},
            "failures": {
                "type": "array",
                "maxItems": 512,
                "items": {"type": "string", "minLength": 1, "maxLength": MAX_FAILURE_CHARS}
            }
        },
        "allOf": [{
            "if": {
                "properties": {"passed": {"const": true}},
                "required": ["passed"]
            },
            "then": {
                "properties": {
                    "failures": {"maxItems": 0},
                    "phases": {
                        "not": {
                            "contains": {
                                "properties": {"passed": {"const": false}},
                                "required": ["passed"]
                            }
                        }
                    }
                }
            },
            "else": {
                "properties": {
                    "failures": {"minItems": 1},
                    "phases": {
                        "contains": {
                            "properties": {"passed": {"const": false}},
                            "required": ["passed"]
                        }
                    }
                }
            }
        }],
        "$defs": {
            "identities": {
                "type": "object",
                "additionalProperties": false,
                "required": ["schematic_sha256", "board_sha256"],
                "properties": {
                    "schematic_sha256": {
                        "type": ["string", "null"],
                        "pattern": "^[0-9a-f]{64}$"
                    },
                    "board_sha256": {
                        "type": ["string", "null"],
                        "pattern": "^[0-9a-f]{64}$"
                    }
                }
            },
            "evidence": {
                "type": "object",
                "additionalProperties": false,
                "required": ["role", "bytes", "sha256"],
                "properties": {
                    "role": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 128,
                        "pattern": "^[a-z0-9][a-z0-9._:-]*$"
                    },
                    "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            }
        }
    })
}

fn phase_schema(name: &str) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "evidence", "passed", "checks", "failures"],
        "properties": {
            "name": {"const": name},
            "evidence": {
                "type": "array",
                "maxItems": 16,
                "items": {"$ref": "#/$defs/evidence"}
            },
            "passed": {"type": "boolean"},
            "checks": {
                "type": "array",
                "maxItems": 128,
                "items": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_CHARS}
            },
            "failures": {
                "type": "array",
                "maxItems": 128,
                "items": {"type": "string", "minLength": 1, "maxLength": MAX_FAILURE_CHARS}
            }
        },
        "allOf": [{
            "if": {
                "properties": {"passed": {"const": true}},
                "required": ["passed"]
            },
            "then": {"properties": {"failures": {"maxItems": 0}}},
            "else": {"properties": {"failures": {"minItems": 1}}}
        }]
    })
}

fn electrical_phase(inputs: &PipelineInputs<'_>) -> (PipelinePhase, Option<String>) {
    let mut phase = PipelinePhase::new("electrical-erc");
    let schematic = capture_snapshot(
        &mut phase,
        inputs.schematic,
        "schematic",
        MAX_SCHEMATIC_BYTES,
    );
    let policy = inputs
        .electrical_policy
        .map(|path| capture_snapshot(&mut phase, path, "electrical-policy", MAX_POLICY_BYTES));
    let review = capture_snapshot(
        &mut phase,
        inputs.electrical_review,
        "electrical-review",
        MAX_REVIEW_BYTES,
    );

    let mut schematic_sha256 = None;
    let schematic_document = schematic.as_ref().and_then(|snapshot| {
        let source = match std::str::from_utf8(&snapshot.bytes) {
            Ok(source) => source,
            Err(error) => {
                phase.fail(format!("schematic is not UTF-8: {error}"));
                return None;
            }
        };
        match import_schematic(source) {
            Ok(document) => {
                match serde_json::to_vec(&document) {
                    Ok(bytes) => schematic_sha256 = Some(sha256(&bytes)),
                    Err(error) => {
                        phase.fail(format!("cannot serialize imported schematic: {error}"));
                        return None;
                    }
                }
                Some(document)
            }
            Err(error) => {
                phase.fail(format!("cannot import schematic: {error}"));
                None
            }
        }
    });

    let effective_policy = match policy {
        None => Some(ElectricalPolicy::default()),
        Some(Some(snapshot)) => match std::str::from_utf8(&snapshot.bytes) {
            Ok(source) => match parse_electrical_policy(source) {
                Ok(policy) => Some(policy),
                Err(error) => {
                    phase.fail(format!("invalid electrical policy: {error}"));
                    None
                }
            },
            Err(error) => {
                phase.fail(format!("electrical policy is not UTF-8: {error}"));
                None
            }
        },
        Some(None) => None,
    };

    let supplied_review = review.as_ref().and_then(|snapshot| {
        match parse_json::<ElectricalReview>(&snapshot.bytes, "electrical review") {
            Ok(review) => {
                if review.findings.len() > MAX_FINDINGS {
                    phase.fail(format!(
                        "electrical review exceeds the {MAX_FINDINGS} finding limit"
                    ));
                    None
                } else {
                    Some(review)
                }
            }
            Err(error) => {
                phase.fail(error);
                None
            }
        }
    });

    if let (Some(schematic), Some(policy), Some(review)) = (
        schematic_document.as_ref(),
        effective_policy.as_ref(),
        supplied_review.as_ref(),
    ) {
        match check_schematic(schematic, policy) {
            Ok(recomputed) => {
                if recomputed != *review {
                    phase.fail(
                        "electrical review does not equal the deterministic schematic/policy recomputation",
                    );
                } else {
                    phase.check("review-recomputed");
                }
                if !review.approved || review.counts.errors != 0 {
                    phase.fail("electrical review is not approved with zero error findings");
                } else {
                    phase.check(format!(
                        "approved=true;errors=0;warnings={};info={}",
                        review.counts.warnings, review.counts.info
                    ));
                }
            }
            Err(error) => phase.fail(format!("cannot recompute electrical review: {error}")),
        }
    }

    (phase.finish(), schematic_sha256)
}

fn analysis_phase(
    inputs: &PipelineInputs<'_>,
) -> (
    PipelinePhase,
    Option<BoardIdentity>,
    Option<AnalysisBinding>,
) {
    let mut phase = PipelinePhase::new("analysis-drc");
    let board = capture_snapshot(&mut phase, inputs.board, "board", MAX_BOARD_BYTES);
    let manifest_snapshot = capture_snapshot(
        &mut phase,
        inputs.analysis_manifest,
        "analysis-manifest",
        MAX_ANALYSIS_BYTES,
    );
    let checks_snapshot = capture_snapshot(
        &mut phase,
        inputs.analysis_checks,
        "analysis-checks",
        MAX_ANALYSIS_BYTES,
    );

    let board_identity = board.as_ref().map(|snapshot| BoardIdentity {
        bytes: snapshot.evidence.bytes,
        sha256: snapshot.evidence.sha256.clone(),
        file_name: inputs
            .board
            .file_name()
            .and_then(|value| value.to_str())
            .map(str::to_string),
    });

    let manifest = manifest_snapshot.as_ref().and_then(|snapshot| {
        match parse_json::<AnalysisManifest>(&snapshot.bytes, "analysis manifest") {
            Ok(manifest) => match validate_analysis_manifest(&manifest) {
                Ok(()) => Some(manifest),
                Err(error) => {
                    phase.fail(error);
                    None
                }
            },
            Err(error) => {
                phase.fail(error);
                None
            }
        }
    });
    let checks = checks_snapshot.as_ref().and_then(|snapshot| {
        match parse_json::<CheckReport>(&snapshot.bytes, "analysis checks") {
            Ok(checks) => match validate_checks(&checks) {
                Ok(()) => Some(checks),
                Err(error) => {
                    phase.fail(error);
                    None
                }
            },
            Err(error) => {
                phase.fail(error);
                None
            }
        }
    });

    let mut binding = None;
    if let (Some(board), Some(board_snapshot), Some(manifest), Some(checks)) = (
        board_identity.as_ref(),
        board.as_ref(),
        manifest.as_ref(),
        checks.as_ref(),
    ) {
        if manifest.input.bytes != board.bytes || manifest.input.sha256 != board.sha256 {
            phase.fail("analysis manifest input does not bind the exact board bytes and SHA-256");
        } else {
            phase.check("board-input-bound");
        }
        let clean = checks.is_clean();
        if manifest.result.clean != clean || manifest.result.violations != checks.violations.len() {
            phase.fail("analysis manifest DRC result does not match checks.json");
        } else {
            phase.check("checks-result-bound");
        }
        if !manifest.result.clean || manifest.result.violations != 0 || !clean {
            phase.fail("analysis/DRC result is not clean with zero violations");
        } else {
            phase.check("clean=true;violations=0");
        }
        if let Some(recomputed_quality) =
            recompute_analysis(&mut phase, inputs, board_snapshot, manifest, checks)
        {
            binding = Some(AnalysisBinding {
                result: manifest.result.clone(),
                recomputed_quality,
            });
        }
    }

    (phase.finish(), board_identity, binding)
}

fn recompute_analysis(
    phase: &mut PipelinePhase,
    inputs: &PipelineInputs<'_>,
    board_snapshot: &Snapshot,
    manifest: &AnalysisManifest,
    supplied_checks: &CheckReport,
) -> Option<RoutingQuality> {
    let source = match std::str::from_utf8(&board_snapshot.bytes) {
        Ok(source) => source,
        Err(error) => {
            phase.fail(format!("board is not UTF-8: {error}"));
            return None;
        }
    };
    let configured_rules = &manifest.configuration.rules;
    let rules = Rules {
        grid_nm: configured_rules.grid_nm,
        track_width_nm: configured_rules.track_width_nm,
        clearance_nm: configured_rules.clearance_nm,
        via_diameter_nm: configured_rules.via_diameter_nm,
        via_drill_nm: configured_rules.via_drill_nm,
        bend_cost: configured_rules.bend_cost,
        via_cost: configured_rules.via_cost,
    };
    let mut imported = match import_kicad(source, rules) {
        Ok(imported) => imported,
        Err(error) => {
            phase.fail(format!("cannot import exact analysis board: {error}"));
            return None;
        }
    };

    let project = capture_optional_descriptor_snapshot(
        phase,
        manifest.project.as_ref(),
        inputs.analysis_project,
        "analysis-project",
        MAX_ANALYSIS_BYTES,
    )?;
    if let Some(snapshot) = project {
        let source = snapshot_utf8(phase, &snapshot, "analysis project")?;
        if let Err(error) = apply_project_net_settings(&mut imported.board, source) {
            phase.fail(format!("cannot apply analysis project settings: {error}"));
            return None;
        }
    }

    let rules_file = capture_optional_descriptor_snapshot(
        phase,
        manifest.rules_file.as_ref(),
        inputs.analysis_rules,
        "analysis-rules",
        MAX_ANALYSIS_BYTES,
    )?;
    if let Some(snapshot) = rules_file {
        let source = snapshot_utf8(phase, &snapshot, "analysis custom rules")?;
        match apply_custom_design_rules(&mut imported.board, source) {
            Ok(applied) if applied == manifest.configuration.applied_custom_rules => {}
            Ok(_) => {
                phase.fail("analysis custom-rule count does not match deterministic recomputation");
                return None;
            }
            Err(error) => {
                phase.fail(format!("cannot apply analysis custom rules: {error}"));
                return None;
            }
        }
    }

    let dfm_profile = capture_optional_descriptor_snapshot(
        phase,
        manifest.dfm_profile_file.as_ref(),
        inputs.analysis_dfm_profile,
        "analysis-dfm-profile",
        MAX_ANALYSIS_BYTES,
    )?;
    if let Some(snapshot) = dfm_profile {
        let source = snapshot_utf8(phase, &snapshot, "analysis DFM profile")?;
        match parse_external_dfm_profile(source) {
            Ok(profile) if manifest.configuration.dfm_profile.as_ref() == Some(&profile) => {}
            Ok(_) => {
                phase.fail("analysis DFM profile does not match its exact source file");
                return None;
            }
            Err(error) => {
                phase.fail(format!("cannot parse analysis DFM profile: {error}"));
                return None;
            }
        }
    }

    let policy_pack = capture_optional_descriptor_snapshot(
        phase,
        manifest.policy_pack_file.as_ref(),
        inputs.analysis_policy_pack,
        "analysis-policy-pack",
        MAX_ANALYSIS_BYTES,
    )?;
    if let Some(snapshot) = policy_pack {
        let source = snapshot_utf8(phase, &snapshot, "analysis policy pack")?;
        match parse_policy_pack(source) {
            Ok(pack)
                if manifest.configuration.organization_policy_pack.as_ref() == Some(&pack.id)
                    && manifest.configuration.dfm_profile.as_ref() == Some(&pack.dfm_profile) => {}
            Ok(_) => {
                phase.fail(
                    "analysis organization policy pack does not match the embedded identity/profile",
                );
                return None;
            }
            Err(error) => {
                phase.fail(format!(
                    "cannot parse analysis organization policy pack: {error}"
                ));
                return None;
            }
        }
    }

    if let Some(profile) = &manifest.configuration.dfm_profile {
        apply_dfm_profile(&mut imported.board, profile);
    }
    let recomputed_checks = check_board(&imported.board);
    let recomputed_quality = routing_quality(&imported.board);
    let checks_match = match (
        serde_json::to_value(&recomputed_checks),
        serde_json::to_value(supplied_checks),
    ) {
        (Ok(recomputed), Ok(supplied)) => recomputed == supplied,
        (Err(error), _) | (_, Err(error)) => {
            phase.fail(format!(
                "cannot compare recomputed analysis checks: {error}"
            ));
            return None;
        }
    };
    if !checks_match {
        phase.fail("checks.json does not equal deterministic board-analysis recomputation");
    } else {
        phase.check("board-checks-recomputed");
    }
    Some(recomputed_quality)
}

fn capture_optional_descriptor_snapshot(
    phase: &mut PipelinePhase,
    descriptor: Option<&AnalysisDescriptor>,
    supplied_path: Option<&Path>,
    role: &str,
    maximum: u64,
) -> Option<Option<Snapshot>> {
    let (descriptor, supplied_path) = match (descriptor, supplied_path) {
        (None, None) => return Some(None),
        (Some(_), None) => {
            phase.fail(format!(
                "{role}: manifest declares this input but no explicit CLI path was supplied"
            ));
            return None;
        }
        (None, Some(_)) => {
            phase.fail(format!(
                "{role}: explicit CLI input is not declared by the analysis manifest"
            ));
            return None;
        }
        (Some(descriptor), Some(supplied_path)) => (descriptor, supplied_path),
    };
    let snapshot = capture_snapshot(phase, supplied_path, role, maximum)?;
    if snapshot.evidence.bytes != descriptor.bytes || snapshot.evidence.sha256 != descriptor.sha256
    {
        phase.fail(format!(
            "{role}: exact file does not match its analysis manifest descriptor"
        ));
        None
    } else {
        phase.check(format!("{role}-bound"));
        Some(Some(snapshot))
    }
}

fn snapshot_utf8<'a>(
    phase: &mut PipelinePhase,
    snapshot: &'a Snapshot,
    label: &str,
) -> Option<&'a str> {
    match std::str::from_utf8(&snapshot.bytes) {
        Ok(source) => Some(source),
        Err(error) => {
            phase.fail(format!("{label} is not UTF-8: {error}"));
            None
        }
    }
}

fn quality_phase(inputs: &PipelineInputs<'_>, analysis: Option<&AnalysisBinding>) -> PipelinePhase {
    let mut phase = PipelinePhase::new("routing-quality");
    let snapshot = capture_snapshot(
        &mut phase,
        inputs.quality,
        "routing-quality",
        MAX_ANALYSIS_BYTES,
    );
    let quality = snapshot.as_ref().and_then(|snapshot| {
        match parse_json::<RoutingQuality>(&snapshot.bytes, "routing quality") {
            Ok(quality) => match validate_quality(&quality) {
                Ok(()) => Some(quality),
                Err(error) => {
                    phase.fail(error);
                    None
                }
            },
            Err(error) => {
                phase.fail(error);
                None
            }
        }
    });

    if let Some(quality) = quality.as_ref() {
        if let Some(analysis) = analysis {
            let result = &analysis.result;
            match (
                serde_json::to_value(quality),
                serde_json::to_value(&analysis.recomputed_quality),
            ) {
                (Ok(supplied), Ok(recomputed)) if supplied == recomputed => {
                    phase.check("board-quality-recomputed");
                }
                (Ok(_), Ok(_)) => {
                    phase.fail(
                        "quality.json does not equal deterministic board-analysis recomputation",
                    );
                }
                (Err(error), _) | (_, Err(error)) => {
                    phase.fail(format!(
                        "cannot compare recomputed routing quality: {error}"
                    ));
                }
            }
            if result.routed_nets != quality.routed_nets
                || result.unrouted_nets != quality.unrouted_nets
                || result.total_length_nm != quality.total_length_nm
                || result.total_vias != quality.total_vias
            {
                phase.fail("analysis manifest routing result does not match quality.json");
            } else {
                phase.check("analysis-quality-bound");
            }
        } else {
            phase.fail("validated analysis manifest is unavailable for quality binding");
        }
        if quality.unrouted_nets != 0 {
            phase.fail(format!(
                "routing quality contains {} unrouted net(s)",
                quality.unrouted_nets
            ));
        } else {
            phase.check(format!(
                "unrouted=0;routed={};length_nm={};vias={}",
                quality.routed_nets, quality.total_length_nm, quality.total_vias
            ));
        }
    }
    phase.finish()
}

fn manufacturing_phase(
    inputs: &PipelineInputs<'_>,
    board: Option<&BoardIdentity>,
) -> (PipelinePhase, Option<ManufacturingIdentity>) {
    let mut phase = PipelinePhase::new("manufacturing-package");
    let mut manufacturing_identity = None;
    let package = capture_snapshot(
        &mut phase,
        inputs.manufacturing_package,
        "manufacturing-package",
        MAX_PACKAGE_BYTES,
    );
    if let Some(package) = package {
        manufacturing_identity = Some(ManufacturingIdentity {
            bytes: package.evidence.bytes,
            sha256: package.evidence.sha256.clone(),
        });
        match validate_manufacturing_package(&package.bytes) {
            Ok(identity) => {
                phase.check("complete-package-validated");
                if let Some(board) = board {
                    if identity.input_bytes != board.bytes || identity.input_sha256 != board.sha256
                    {
                        phase.fail(
                            "manufacturing package input does not bind the exact board bytes and SHA-256",
                        );
                    } else {
                        phase.check("manufacturing-board-bound");
                    }
                    match board.file_name.as_deref() {
                        Some(file_name) if identity.input_path == file_name => {
                            phase.check("manufacturing-board-name-bound");
                        }
                        Some(_) => phase.fail(
                            "manufacturing package input filename does not match the exact board",
                        ),
                        None => phase.fail("board filename is not valid UTF-8"),
                    }
                } else {
                    phase.fail("exact board identity is unavailable for manufacturing binding");
                }
            }
            Err(error) => phase.fail(format!("invalid manufacturing package: {error}")),
        }
    }
    let phase = phase.finish();
    if phase.passed {
        (phase, manufacturing_identity)
    } else {
        (phase, None)
    }
}

fn firmware_phase(inputs: &PipelineInputs<'_>, schematic_sha256: Option<&str>) -> PipelinePhase {
    let mut phase = PipelinePhase::new("firmware-build");
    let manifest_snapshot = capture_snapshot(
        &mut phase,
        inputs.firmware_manifest,
        "firmware-manifest",
        MAX_FIRMWARE_MANIFEST_BYTES,
    );
    if manifest_snapshot.is_some() {
        validate_firmware_bundle_directory(&mut phase, inputs.firmware_manifest);
    }
    let manifest = manifest_snapshot.as_ref().and_then(|snapshot| {
        match parse_json::<FirmwareManifest>(&snapshot.bytes, "firmware manifest") {
            Ok(manifest) => Some(manifest),
            Err(error) => {
                phase.fail(error);
                None
            }
        }
    });

    if let Some(manifest) = manifest.as_ref() {
        // Keep manifest shape failures independent from the evidence checks.  A
        // malformed engine/version or artifact descriptor must not hide a
        // missing/failed C, C++, or Python build evidence record.
        let manifest_shape_valid = match validate_firmware_manifest(manifest) {
            Ok(()) => true,
            Err(error) => {
                phase.fail(error);
                false
            }
        };

        match schematic_sha256 {
            Some(expected) if manifest.schematic_sha256 == expected => {
                phase.check("firmware-schematic-bound");
            }
            Some(_) => phase.fail("firmware manifest is bound to a different schematic"),
            None => phase.fail("exact schematic identity is unavailable for firmware binding"),
        }
        validate_firmware_build(&mut phase, "c-build", &manifest.c_build);
        validate_firmware_build(&mut phase, "cpp-build", &manifest.cpp_build);
        validate_firmware_build(&mut phase, "python-check", &manifest.python_check);

        // Do not use untrusted artifact paths unless the complete descriptor
        // set has passed validation.  Once shape-checked, retain the existing
        // bounded, regular-file, anti-symlink snapshot and hash binding logic.
        if manifest_shape_valid {
            let parent = inputs
                .firmware_manifest
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            for descriptor in &manifest.artifacts {
                let role = format!("firmware-artifact:{}", descriptor.path);
                match read_snapshot(
                    &parent.join(&descriptor.path),
                    &role,
                    MAX_FIRMWARE_ARTIFACT_BYTES,
                ) {
                    Ok(snapshot) => {
                        if snapshot.evidence.bytes != descriptor.bytes
                            || snapshot.evidence.sha256 != descriptor.sha256
                        {
                            phase.fail(format!(
                                "firmware artifact {} does not match its bytes/SHA-256 descriptor",
                                descriptor.path
                            ));
                        } else {
                            phase.check(format!("hash-ok:{}", descriptor.path));
                        }
                        phase.evidence.push(snapshot.evidence);
                    }
                    Err(error) => phase.fail(error),
                }
            }
        }
    }
    phase.finish()
}

fn validate_firmware_bundle_directory(phase: &mut PipelinePhase, manifest_path: &Path) {
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("manifest.json") {
        phase.fail("firmware v2 manifest filename must be manifest.json");
        return;
    }
    let parent = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut actual = Vec::new();
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) => {
            phase.fail(format!("cannot list firmware bundle directory: {error}"));
            return;
        }
    };
    for entry in entries {
        if actual.len() > FIRMWARE_ARTIFACTS.len() {
            phase.fail(
                "firmware bundle directory does not contain the exact v2 artifact set: entry limit exceeded",
            );
            return;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                phase.fail(format!("cannot inspect firmware bundle entry: {error}"));
                return;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                phase.fail(format!(
                    "cannot inspect firmware bundle entry type: {error}"
                ));
                return;
            }
        };
        if file_type.is_symlink() || !file_type.is_file() {
            phase.fail("firmware bundle directory contains a non-regular entry");
            return;
        }
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => {
                phase.fail("firmware bundle directory contains a non-UTF-8 filename");
                return;
            }
        };
        actual.push(name);
    }
    actual.sort();
    let mut expected = FIRMWARE_ARTIFACTS
        .iter()
        .map(ToString::to_string)
        .chain(std::iter::once("manifest.json".to_string()))
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        phase.fail("firmware bundle directory does not contain the exact v2 artifact set");
    } else {
        phase.check("firmware-directory-exact");
    }
}

fn factory_phase(
    receipt_path: Option<&Path>,
    manufacturing: Option<&ManufacturingIdentity>,
) -> PipelinePhase {
    let mut phase = PipelinePhase::new("factory-dfm");
    let Some(receipt_path) = receipt_path else {
        phase.fail("factory receipt is required for the factory-bound pipeline");
        return phase.finish();
    };
    let receipt_snapshot = capture_snapshot(
        &mut phase,
        receipt_path,
        "factory-receipt",
        MAX_FACTORY_RECEIPT_BYTES,
    );
    let receipt = receipt_snapshot.as_ref().and_then(|snapshot| {
        match parse_json::<FactorySubmissionReceipt>(&snapshot.bytes, "factory receipt") {
            Ok(receipt) => match validate_factory_submission_receipt(&receipt, false) {
                Ok(()) => {
                    phase.check("factory-receipt-validated");
                    Some(receipt)
                }
                Err(error) => {
                    phase.fail(format!("invalid factory receipt: {error}"));
                    None
                }
            },
            Err(error) => {
                phase.fail(error);
                None
            }
        }
    });

    if let Some(receipt) = receipt.as_ref() {
        match manufacturing {
            Some(identity)
                if receipt.package_bytes == identity.bytes
                    && receipt.package_sha256 == identity.sha256
                    && receipt.request_sha256 == identity.sha256 =>
            {
                phase.check("factory-package-bound");
            }
            Some(_) => phase.fail(
                "factory receipt package/request identity does not match the exact validated manufacturing ZIP",
            ),
            None => phase.fail(
                "exact validated manufacturing package identity is unavailable for factory binding",
            ),
        }
        if factory_feedback_passed(receipt) {
            phase.check("factory-dfm=passed");
        } else {
            phase.fail(
                "factory receipt did not pass accepted, DFM, HTTP, and fail-closed severity policy",
            );
        }
    }
    phase.finish()
}

fn capture_snapshot(
    phase: &mut PipelinePhase,
    path: &Path,
    role: &str,
    maximum: u64,
) -> Option<Snapshot> {
    match read_snapshot(path, role, maximum) {
        Ok(snapshot) => {
            phase.evidence.push(snapshot.evidence.clone());
            Some(snapshot)
        }
        Err(error) => {
            phase.fail(error);
            None
        }
    }
}

fn read_snapshot(path: &Path, role: &str, maximum: u64) -> Result<Snapshot, String> {
    reject_symlink_components(path, role)?;
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("{role}: cannot inspect input: {error}"))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        return Err(format!(
            "{role}: input must be a real regular file, not a symlink"
        ));
    }
    if path_metadata.len() == 0 || path_metadata.len() > maximum {
        return Err(format!("{role}: input must contain 1 to {maximum} bytes"));
    }
    let mut file =
        File::open(path).map_err(|error| format!("{role}: cannot open input: {error}"))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| format!("{role}: cannot inspect opened input: {error}"))?;
    if !opened_metadata.is_file() {
        return Err(format!("{role}: opened input is not a regular file"));
    }
    verify_same_file(&path_metadata, &opened_metadata, role)?;
    if opened_metadata.len() == 0 || opened_metadata.len() > maximum {
        return Err(format!(
            "{role}: opened input must contain 1 to {maximum} bytes"
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{role}: cannot read input: {error}"))?;
    if bytes.is_empty() || bytes.len() as u64 > maximum {
        return Err(format!("{role}: input must contain 1 to {maximum} bytes"));
    }
    let final_metadata = file
        .metadata()
        .map_err(|error| format!("{role}: cannot re-inspect input: {error}"))?;
    verify_same_file(&opened_metadata, &final_metadata, role)?;
    if final_metadata.len() != opened_metadata.len() || bytes.len() as u64 != opened_metadata.len()
    {
        return Err(format!("{role}: input changed while it was being read"));
    }
    let evidence = PipelineEvidence {
        role: role.to_string(),
        bytes: bytes.len() as u64,
        sha256: sha256(&bytes),
    };
    Ok(Snapshot { bytes, evidence })
}

fn reject_symlink_components(path: &Path, role: &str) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("{role}: cannot resolve current directory: {error}"))?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{role}: input path contains a symlink component"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "{role}: cannot inspect an input path component: {error}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_same_file(before: &fs::Metadata, after: &fs::Metadata, role: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        Err(format!("{role}: input changed while it was being opened"))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn verify_same_file(
    _before: &fs::Metadata,
    _after: &fs::Metadata,
    _role: &str,
) -> Result<(), String> {
    Ok(())
}

fn parse_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T, String> {
    serde_json::from_slice(bytes).map_err(|error| format!("invalid {label} JSON: {error}"))
}

fn validate_analysis_manifest(manifest: &AnalysisManifest) -> Result<(), String> {
    if manifest.schema_version != 1
        || manifest.engine != "pcbex"
        || manifest.command != "analyze-kicad"
    {
        return Err("analysis manifest is not a pcbex analyze-kicad v1 report".into());
    }
    validate_text(&manifest.engine_version, "analysis engine version")?;
    validate_analysis_descriptor(&manifest.input, "analysis input", MAX_BOARD_BYTES)?;
    for (label, descriptor) in [
        ("analysis project", manifest.project.as_ref()),
        ("analysis rules file", manifest.rules_file.as_ref()),
        ("analysis DFM profile", manifest.dfm_profile_file.as_ref()),
        ("analysis policy pack", manifest.policy_pack_file.as_ref()),
    ] {
        if let Some(descriptor) = descriptor {
            validate_analysis_descriptor(descriptor, label, MAX_ANALYSIS_BYTES)?;
        }
    }
    if manifest.configuration.project_settings_loaded != manifest.project.is_some() {
        return Err("analysis project descriptor and configuration disagree".into());
    }
    if manifest.rules_file.is_none() && manifest.configuration.applied_custom_rules != 0 {
        return Err("analysis custom-rule count has no rules-file descriptor".into());
    }
    if manifest.configuration.applied_custom_rules > MAX_VIOLATIONS {
        return Err("analysis custom-rule count exceeds its limit".into());
    }
    if manifest.configuration.organization_policy_pack.is_some()
        != manifest.policy_pack_file.is_some()
    {
        return Err("analysis policy-pack identity and descriptor disagree".into());
    }
    if let Some(id) = &manifest.configuration.organization_policy_pack {
        validate_text(id, "analysis organization policy-pack id")?;
    }
    validate_rules(&manifest.configuration.rules)?;
    if let Some(profile) = &manifest.configuration.dfm_profile {
        validate_dfm_profile(profile)
            .map_err(|error| format!("invalid analysis DFM profile: {error}"))?;
    }
    if !manifest
        .artifacts
        .iter()
        .map(String::as_str)
        .eq(ANALYSIS_ARTIFACTS)
    {
        return Err("analysis manifest does not declare the exact v1 artifact set".into());
    }
    if manifest.result.violations > MAX_VIOLATIONS
        || manifest.result.routed_nets > MAX_NETS
        || manifest.result.unrouted_nets > MAX_NETS
        || manifest.result.total_length_nm < 0
    {
        return Err("analysis manifest result contains invalid or excessive counts".into());
    }
    Ok(())
}

fn validate_analysis_descriptor(
    descriptor: &AnalysisDescriptor,
    label: &str,
    maximum: u64,
) -> Result<(), String> {
    validate_text(&descriptor.path, label)?;
    if descriptor.bytes == 0 || descriptor.bytes > maximum {
        return Err(format!("{label} has an invalid byte count"));
    }
    if !is_sha256(&descriptor.sha256) {
        return Err(format!("{label} has an invalid SHA-256"));
    }
    Ok(())
}

fn validate_rules(rules: &StrictRules) -> Result<(), String> {
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

fn validate_checks(checks: &CheckReport) -> Result<(), String> {
    if checks.violations.len() > MAX_VIOLATIONS {
        return Err(format!(
            "analysis checks exceed the {MAX_VIOLATIONS} violation limit"
        ));
    }
    for violation in &checks.violations {
        validate_text(&violation.rule, "analysis violation rule")?;
        validate_text(&violation.message, "analysis violation message")?;
        if violation.net_ids.len() > MAX_NETS {
            return Err("analysis violation net-id list exceeds its limit".into());
        }
        let mut ids = BTreeSet::new();
        if violation
            .net_ids
            .iter()
            .any(|id| *id == 0 || !ids.insert(*id))
        {
            return Err("analysis violation contains zero or duplicate net ids".into());
        }
    }
    Ok(())
}

fn validate_quality(quality: &RoutingQuality) -> Result<(), String> {
    if quality.nets.len() > MAX_NETS || quality.differential_pairs.len() > MAX_NETS {
        return Err(format!("routing quality exceeds the {MAX_NETS} net limit"));
    }
    if quality.total_length_nm < 0 {
        return Err("routing quality total length must not be negative".into());
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    let mut routed = 0_usize;
    let mut total_length = 0_i64;
    let mut total_vias = 0_usize;
    let mut total_bends = 0_usize;
    for net in &quality.nets {
        if net.net_id == 0 || !ids.insert(net.net_id) {
            return Err("routing quality contains zero or duplicate net ids".into());
        }
        validate_text(&net.name, "routing-quality net name")?;
        if !names.insert(net.name.as_str()) {
            return Err("routing quality contains duplicate net names".into());
        }
        if net.length_nm < 0 {
            return Err("routing quality contains a negative net length".into());
        }
        if !net.routed
            && (net.length_nm != 0
                || net.segments != 0
                || net.arcs != 0
                || net.vias != 0
                || net.bends != 0
                || net.layers_used != 0)
        {
            return Err("unrouted quality entries must have zero routing metrics".into());
        }
        routed = routed
            .checked_add(usize::from(net.routed))
            .ok_or_else(|| "routing-quality routed count overflow".to_string())?;
        total_length = total_length
            .checked_add(net.length_nm)
            .ok_or_else(|| "routing-quality length overflow".to_string())?;
        total_vias = total_vias
            .checked_add(net.vias)
            .ok_or_else(|| "routing-quality via count overflow".to_string())?;
        total_bends = total_bends
            .checked_add(net.bends)
            .ok_or_else(|| "routing-quality bend count overflow".to_string())?;
    }
    let unrouted = quality
        .nets
        .len()
        .checked_sub(routed)
        .ok_or_else(|| "routing-quality routed count is invalid".to_string())?;
    if quality.routed_nets != routed
        || quality.unrouted_nets != unrouted
        || quality.total_length_nm != total_length
        || quality.total_vias != total_vias
        || quality.total_bends != total_bends
    {
        return Err("routing quality aggregate metrics are inconsistent".into());
    }
    let mut pair_names = BTreeSet::new();
    for pair in &quality.differential_pairs {
        validate_text(&pair.name, "differential-pair quality name")?;
        if !pair_names.insert(pair.name.as_str()) {
            return Err("routing quality contains duplicate differential-pair names".into());
        }
        if pair.positive_length_nm < 0
            || pair.negative_length_nm < 0
            || pair.skew_nm < 0
            || pair.coupled_percent > 100
        {
            return Err("routing quality contains invalid differential-pair metrics".into());
        }
        let skew = pair.positive_length_nm.abs_diff(pair.negative_length_nm);
        if skew > i64::MAX as u64 || pair.skew_nm != skew as i64 {
            return Err("routing quality differential-pair skew is inconsistent".into());
        }
    }
    Ok(())
}

fn validate_firmware_manifest(manifest: &FirmwareManifest) -> Result<(), String> {
    if manifest.schema_version != FIRMWARE_SCHEMA_VERSION {
        return Err(format!(
            "firmware manifest schema_version must be {FIRMWARE_SCHEMA_VERSION}"
        ));
    }
    if manifest.engine != "pcbex" {
        return Err("firmware manifest engine must be pcbex".into());
    }
    if !is_semver_like(&manifest.engine_version) {
        return Err("firmware manifest engine version must be a bounded semantic version".into());
    }
    if !is_sha256(&manifest.schematic_sha256) {
        return Err("firmware manifest has an invalid schematic SHA-256".into());
    }
    if manifest.artifacts.len() != FIRMWARE_ARTIFACTS.len()
        || !manifest
            .artifacts
            .iter()
            .map(|artifact| artifact.path.as_str())
            .eq(FIRMWARE_ARTIFACTS)
    {
        return Err("firmware manifest must list the exact ordered v2 artifact set".into());
    }
    let mut total = 0_u64;
    for artifact in &manifest.artifacts {
        if !is_safe_firmware_name(&artifact.path) {
            return Err("firmware manifest contains an unsafe artifact path".into());
        }
        if artifact.bytes == 0 || artifact.bytes > MAX_FIRMWARE_ARTIFACT_BYTES {
            return Err(format!(
                "firmware artifact {} has an invalid byte count",
                artifact.path
            ));
        }
        if !is_sha256(&artifact.sha256) {
            return Err(format!(
                "firmware artifact {} has an invalid SHA-256",
                artifact.path
            ));
        }
        total = total
            .checked_add(artifact.bytes)
            .ok_or_else(|| "firmware artifact byte-count overflow".to_string())?;
        if total > MAX_FIRMWARE_TOTAL_BYTES {
            return Err("firmware artifacts exceed the total byte limit".into());
        }
    }
    Ok(())
}

fn validate_firmware_build(phase: &mut PipelinePhase, label: &str, build: &FirmwareBuildEvidence) {
    validate_firmware_evidence(
        phase,
        label,
        build.attempted,
        build.passed,
        build.exit_code,
        &build.command,
    );
    validate_firmware_command_evidence(phase, &format!("{label}-smoke"), &build.smoke);
}

fn validate_firmware_command_evidence(
    phase: &mut PipelinePhase,
    label: &str,
    evidence: &FirmwareCommandEvidence,
) {
    validate_firmware_evidence(
        phase,
        label,
        evidence.attempted,
        evidence.passed,
        evidence.exit_code,
        &evidence.command,
    );
}

fn validate_firmware_evidence(
    phase: &mut PipelinePhase,
    label: &str,
    attempted: bool,
    passed: bool,
    exit_code: Option<i32>,
    command: &[String],
) {
    if !attempted {
        phase.fail(format!("firmware {label} was not attempted"));
    }
    if !passed {
        phase.fail(format!("firmware {label} did not pass"));
    }
    if exit_code != Some(0) {
        phase.fail(format!("firmware {label} exit code is not zero"));
    }
    validate_firmware_command(phase, label, command);
    if attempted && passed && exit_code == Some(0) {
        phase.check(format!("{label}=passed"));
    }
}

fn validate_firmware_command(phase: &mut PipelinePhase, label: &str, command: &[String]) {
    if command.is_empty() || command.len() > MAX_COMMAND_ARGUMENTS {
        phase.fail(format!(
            "firmware {label} command has an invalid argument count"
        ));
        return;
    }
    for argument in command {
        if let Err(error) = validate_text(argument, &format!("firmware {label} command argument")) {
            phase.fail(error);
            continue;
        }
        if !argument.bytes().all(|byte| (b' '..=b'~').contains(&byte)) {
            phase.fail(format!(
                "firmware {label} command arguments must contain printable ASCII only"
            ));
        }
    }
}

fn is_safe_firmware_name(path: &str) -> bool {
    !path.is_empty()
        && !path.contains('/')
        && !path.contains('\\')
        && !path.contains('\0')
        && !path.chars().any(char::is_control)
        && path != "."
        && path != ".."
}

fn validate_text(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty()
        || value.trim() != value
        || value.chars().count() > MAX_TEXT_CHARS
        || value.contains('\0')
    {
        return Err(format!(
            "{label} must contain 1 to {MAX_TEXT_CHARS} trimmed characters"
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_semver_like(value: &str) -> bool {
    if value.len() < 5 || value.len() > 128 || !value.is_ascii() {
        return false;
    }
    let (without_build, build) = value
        .split_once('+')
        .map_or((value, None), |(core, suffix)| (core, Some(suffix)));
    if build.is_some_and(|suffix| !is_semver_suffix(suffix)) || without_build.contains('+') {
        return false;
    }
    let (core, prerelease) = without_build
        .split_once('-')
        .map_or((without_build, None), |(core, suffix)| (core, Some(suffix)));
    if prerelease.is_some_and(|suffix| !is_semver_suffix(suffix)) {
        return false;
    }
    let mut parts = core.split('.');
    let valid_core = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    valid_core && parts.next().is_none()
}

fn is_semver_suffix(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn bound_text(value: &str, maximum: usize) -> String {
    if value.chars().count() <= maximum {
        return value.to_string();
    }
    value.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::tempdir;

    fn all_inputs(path: &Path) -> PipelineInputs<'_> {
        PipelineInputs {
            schematic: path,
            electrical_policy: None,
            electrical_review: path,
            board: path,
            analysis_manifest: path,
            analysis_checks: path,
            quality: path,
            analysis_project: None,
            analysis_rules: None,
            analysis_dfm_profile: None,
            analysis_policy_pack: None,
            manufacturing_package: path,
            firmware_manifest: path,
            factory_receipt: None,
            require_factory: false,
        }
    }

    #[test]
    fn missing_inputs_fail_closed_without_serializing_host_paths() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("secret-missing-input.json");
        let report = verify_pipeline(&all_inputs(&missing));
        assert!(!report.passed);
        assert_eq!(report.phases.len(), 5);
        assert!(report.phases.iter().all(|phase| !phase.passed));
        assert_eq!(report.identities.schematic_sha256, None);
        assert_eq!(report.identities.board_sha256, None);
        let rendered = serde_json::to_string(&report).unwrap();
        assert!(!rendered.contains(directory.path().to_string_lossy().as_ref()));
        assert!(!rendered.contains("secret-missing-input"));
    }

    #[test]
    fn bounded_reader_rejects_empty_and_oversized_files() {
        let directory = tempdir().unwrap();
        let empty = directory.path().join("empty");
        fs::write(&empty, []).unwrap();
        assert!(read_snapshot(&empty, "fixture", 4).is_err());
        let oversized = directory.path().join("oversized");
        fs::write(&oversized, b"12345").unwrap();
        assert!(
            read_snapshot(&oversized, "fixture", 4)
                .unwrap_err()
                .contains("1 to 4 bytes")
        );
    }

    #[test]
    fn analysis_descriptors_require_explicit_paths_and_never_authorize_their_own_paths() {
        let directory = tempdir().unwrap();
        let supplied = directory.path().join("explicit-project.json");
        fs::write(&supplied, b"explicit bytes").unwrap();
        let descriptor = AnalysisDescriptor {
            path: "/untrusted/host/secret".into(),
            bytes: 14,
            sha256: sha256(b"explicit bytes"),
        };

        let mut missing = PipelinePhase::new("analysis-drc");
        assert!(
            capture_optional_descriptor_snapshot(
                &mut missing,
                Some(&descriptor),
                None,
                "analysis-project",
                64,
            )
            .is_none()
        );
        assert!(missing.evidence.is_empty());
        assert!(
            missing
                .failures
                .iter()
                .any(|failure| failure.contains("no explicit CLI path"))
        );

        let mut explicit = PipelinePhase::new("analysis-drc");
        let snapshot = capture_optional_descriptor_snapshot(
            &mut explicit,
            Some(&descriptor),
            Some(&supplied),
            "analysis-project",
            64,
        )
        .flatten()
        .unwrap();
        assert_eq!(snapshot.bytes, b"explicit bytes");
        assert_eq!(explicit.evidence.len(), 1);
        assert!(explicit.failures.is_empty());

        let mut undeclared = PipelinePhase::new("analysis-drc");
        assert!(
            capture_optional_descriptor_snapshot(
                &mut undeclared,
                None,
                Some(&supplied),
                "analysis-project",
                64,
            )
            .is_none()
        );
        assert!(
            undeclared
                .failures
                .iter()
                .any(|failure| failure.contains("not declared"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_rejects_direct_and_parent_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempdir().unwrap();
        let real = directory.path().join("real");
        fs::write(&real, b"data").unwrap();
        let link = directory.path().join("link");
        symlink(&real, &link).unwrap();
        assert!(read_snapshot(&link, "fixture", 16).is_err());

        let real_parent = directory.path().join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        fs::write(real_parent.join("data"), b"data").unwrap();
        let linked_parent = directory.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        assert!(
            read_snapshot(&linked_parent.join("data"), "fixture", 16)
                .unwrap_err()
                .contains("symlink component")
        );
    }

    #[test]
    fn firmware_manifest_is_closed_and_artifacts_are_hash_bound() {
        let directory = tempdir().unwrap();
        let artifacts = FIRMWARE_ARTIFACTS
            .iter()
            .map(|name| {
                fs::write(directory.path().join(name), b"source").unwrap();
                json!({"path": name, "bytes": 6, "sha256": sha256(b"source")})
            })
            .collect::<Vec<_>>();
        let manifest_path = directory.path().join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&json!({
                "schema_version": FIRMWARE_SCHEMA_VERSION,
                "engine": "pcbex",
                "engine_version": env!("CARGO_PKG_VERSION"),
                "schematic_sha256": "a".repeat(64),
                "artifacts": artifacts,
                "c_build": {
                    "attempted": true,
                    "passed": true,
                    "command": ["cc"],
                    "exit_code": 0,
                    "smoke": {
                        "attempted": true,
                        "passed": true,
                        "command": ["firmware-c-smoke"],
                        "exit_code": 0
                    }
                },
                "cpp_build": {
                    "attempted": true,
                    "passed": true,
                    "command": ["c++"],
                    "exit_code": 0,
                    "smoke": {
                        "attempted": true,
                        "passed": true,
                        "command": ["firmware-cpp-smoke"],
                        "exit_code": 0
                    }
                },
                "python_check": {
                    "attempted": true,
                    "passed": true,
                    "command": ["python3"],
                    "exit_code": 0,
                    "smoke": {
                        "attempted": true,
                        "passed": true,
                        "command": ["python3", "host.py"],
                        "exit_code": 0
                    }
                },
                "unknown": true
            }))
            .unwrap(),
        )
        .unwrap();
        let inputs = all_inputs(&manifest_path);
        let phase = firmware_phase(&inputs, Some(&"a".repeat(64)));
        assert!(!phase.passed);
        assert!(
            phase
                .failures
                .iter()
                .any(|failure| failure.contains("unknown field"))
        );

        let mut manifest = json!({
            "schema_version": FIRMWARE_SCHEMA_VERSION,
            "engine": "pcbex",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "schematic_sha256": "a".repeat(64),
            "artifacts": FIRMWARE_ARTIFACTS.iter().map(|name| {
                json!({"path": name, "bytes": 6, "sha256": sha256(b"source")})
            }).collect::<Vec<_>>(),
            "c_build": {
                "attempted": true,
                "passed": true,
                "command": ["cc"],
                "exit_code": 0,
                "smoke": {
                    "attempted": true,
                    "passed": true,
                    "command": ["firmware-c-smoke"],
                    "exit_code": 0
                }
            },
            "cpp_build": {
                "attempted": true,
                "passed": true,
                "command": ["c++"],
                "exit_code": 0,
                "smoke": {
                    "attempted": true,
                    "passed": true,
                    "command": ["firmware-cpp-smoke"],
                    "exit_code": 0
                }
            },
            "python_check": {
                "attempted": true,
                "passed": true,
                "command": ["python3"],
                "exit_code": 0,
                "smoke": {
                    "attempted": true,
                    "passed": true,
                    "command": ["python3", "host.py"],
                    "exit_code": 0
                }
            }
        });
        manifest["artifacts"][0]["sha256"] = Value::String("b".repeat(64));
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let phase = firmware_phase(&inputs, Some(&"a".repeat(64)));
        assert!(!phase.passed);
        assert!(
            phase
                .failures
                .iter()
                .any(|failure| failure.contains("does not match"))
        );
    }

    #[test]
    fn firmware_gate_accumulates_cpp_python_smoke_and_version_failures() {
        let directory = tempdir().unwrap();
        let artifacts = FIRMWARE_ARTIFACTS
            .iter()
            .map(|name| {
                fs::write(directory.path().join(name), b"source").unwrap();
                json!({"path": name, "bytes": 6, "sha256": sha256(b"source")})
            })
            .collect::<Vec<_>>();
        let manifest_path = directory.path().join("manifest.json");
        let mut manifest = json!({
            "schema_version": FIRMWARE_SCHEMA_VERSION,
            "engine": "pcbex",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "schematic_sha256": "a".repeat(64),
            "artifacts": artifacts,
            "c_build": {
                "attempted": true,
                "passed": true,
                "command": ["cc"],
                "exit_code": 0,
                "smoke": {
                    "attempted": true,
                    "passed": true,
                    "command": ["firmware-c-smoke"],
                    "exit_code": 0
                }
            },
            "cpp_build": {
                "attempted": true,
                "passed": true,
                "command": ["c++"],
                "exit_code": 0,
                "smoke": {
                    "attempted": true,
                    "passed": true,
                    "command": ["firmware-cpp-smoke"],
                    "exit_code": 0
                }
            },
            "python_check": {
                "attempted": true,
                "passed": true,
                "command": ["python3"],
                "exit_code": 0,
                "smoke": {
                    "attempted": true,
                    "passed": true,
                    "command": ["python3", "host.py"],
                    "exit_code": 0
                }
            }
        });
        let inputs = all_inputs(&manifest_path);

        manifest["cpp_build"]["passed"] = json!(false);
        manifest["python_check"]["smoke"]["exit_code"] = json!(1);
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let phase = firmware_phase(&inputs, Some(&"a".repeat(64)));
        assert!(!phase.passed);
        assert!(
            phase
                .failures
                .iter()
                .any(|failure| failure.contains("cpp-build did not pass"))
        );
        assert!(
            phase
                .failures
                .iter()
                .any(|failure| failure.contains("python-check-smoke exit code"))
        );

        manifest["cpp_build"]["passed"] = json!(true);
        manifest["python_check"]["smoke"]["exit_code"] = json!(0);
        manifest["cpp_build"]["smoke"]["attempted"] = json!(false);
        manifest["engine_version"] = json!("not-this-pcbex-version");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        let phase = firmware_phase(&inputs, Some(&"a".repeat(64)));
        assert!(!phase.passed);
        assert!(
            phase
                .failures
                .iter()
                .any(|failure| failure.contains("cpp-build-smoke was not attempted"))
        );
        assert!(
            phase
                .failures
                .iter()
                .any(|failure| failure.contains("engine version"))
        );
    }

    #[test]
    fn report_schema_is_closed_and_orders_all_five_phases() {
        let schema = pipeline_gate_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["phases"]["minItems"], 5);
        assert_eq!(schema["properties"]["phases"]["maxItems"], 5);
        let names = schema["properties"]["phases"]["prefixItems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|phase| phase["properties"]["name"]["const"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "electrical-erc",
                "analysis-drc",
                "routing-quality",
                "manufacturing-package",
                "firmware-build",
            ]
        );
        assert_eq!(schema["properties"]["phases"]["items"], false);
        assert_eq!(
            schema["allOf"][0]["then"]["properties"]["failures"]["maxItems"],
            0
        );
        assert_eq!(schema["$defs"]["evidence"]["additionalProperties"], false);
        for phase in schema["properties"]["phases"]["prefixItems"]
            .as_array()
            .unwrap()
        {
            assert_eq!(
                phase["allOf"][0]["then"]["properties"]["failures"]["maxItems"],
                0
            );
            assert_eq!(
                phase["allOf"][0]["else"]["properties"]["failures"]["minItems"],
                1
            );
        }
    }

    #[test]
    fn factory_report_schema_is_closed_and_appends_the_sixth_phase() {
        let schema = pipeline_factory_gate_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["schema_version"]["const"], 2);
        assert_eq!(
            schema["properties"]["pipeline"]["const"],
            "pcbex-hardware-v2"
        );
        assert_eq!(schema["properties"]["phases"]["minItems"], 6);
        assert_eq!(schema["properties"]["phases"]["maxItems"], 6);
        let names = schema["properties"]["phases"]["prefixItems"]
            .as_array()
            .unwrap()
            .iter()
            .map(|phase| phase["properties"]["name"]["const"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "electrical-erc",
                "analysis-drc",
                "routing-quality",
                "manufacturing-package",
                "firmware-build",
                "factory-dfm",
            ]
        );
        assert_eq!(schema["properties"]["phases"]["items"], false);
    }

    #[test]
    fn quality_validation_rejects_inconsistent_aggregates() {
        let quality: RoutingQuality = serde_json::from_value(json!({
            "total_length_nm": 10,
            "total_vias": 0,
            "total_bends": 0,
            "routed_nets": 1,
            "unrouted_nets": 0,
            "nets": [{
                "net_id": 1,
                "name": "N",
                "routed": true,
                "length_nm": 9,
                "segments": 1,
                "arcs": 0,
                "vias": 0,
                "bends": 0,
                "layers_used": 1
            }],
            "differential_pairs": []
        }))
        .unwrap();
        assert!(validate_quality(&quality).is_err());
    }

    #[test]
    fn snapshot_hashes_exact_streamed_bytes() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("artifact");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"exact bytes").unwrap();
        file.sync_all().unwrap();
        let snapshot = read_snapshot(&path, "artifact", 64).unwrap();
        assert_eq!(snapshot.evidence.bytes, 11);
        assert_eq!(snapshot.evidence.sha256, sha256(b"exact bytes"));
    }
}
