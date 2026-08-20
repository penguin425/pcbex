//! Fresh exact verification for retained routing-convergence evidence.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::policy_pack::parse_policy_pack;
use anyhow::{Context, Result, bail};
use pcbex_core::{
    Board, DfmProfile, MAX_DFM_PROFILE_TEXT_BYTES, MAX_ROUTING_CONVERGENCE_REPORT_BYTES,
    PhysicalConstraintProfile, RoutingConvergenceReport, RoutingConvergenceStatus, Rules,
    apply_dfm_profile, apply_physical_profile, dfm_profile, parse_board_json,
    parse_external_dfm_profile, parse_physical_profile, render_routing_convergence_report,
    routing_convergence_report_json_schema, verify_routing_convergence_report,
};
use pcbex_kicad::{
    ExactArtifactIdentity, apply_custom_design_rules, apply_project_net_settings,
    import as import_kicad,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const MAX_ROUTING_CONVERGENCE_VERIFICATION_REPORT_BYTES: u64 = 32 * 1024 * 1024;
pub(crate) const MAX_ROUTING_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_ROUTING_POLICY_PACK_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_ROUTING_PROFILE_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const MAX_BOARD_JSON_ROUTING_VERIFICATION_INPUT_BYTES: u64 = 276 * 1024 * 1024;
pub(crate) const MAX_KICAD_ROUTING_VERIFICATION_INPUT_BYTES: u64 = 592 * 1024 * 1024;

const BINDING_DOMAIN: &[u8] = b"pcbex/fresh-exact-routing-convergence-verification/v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RoutingConvergenceVerificationInputKind {
    BoardJson,
    KicadPcb,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum RoutingConvergenceVerificationStatus {
    #[serde(rename = "verified_complete")]
    Complete,
    #[serde(rename = "verified_partial")]
    Partial,
    #[serde(rename = "verified_no_admissible_candidate")]
    NoAdmissibleCandidate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoutingConvergenceVerificationSources {
    pub input: ExactArtifactIdentity,
    pub routed_output: ExactArtifactIdentity,
    pub retained_report: ExactArtifactIdentity,
    pub project: Option<ExactArtifactIdentity>,
    pub rules_file: Option<ExactArtifactIdentity>,
    pub fab_profile: Option<ExactArtifactIdentity>,
    pub policy_pack: Option<ExactArtifactIdentity>,
    pub physical_profile: Option<ExactArtifactIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoutingConvergenceVerificationChecks {
    pub source_closure_captured: bool,
    pub retained_report_canonical: bool,
    pub fresh_convergence_replayed: bool,
    pub retained_report_exact: bool,
    pub routed_output_exact: bool,
    pub caller_inputs_unchanged: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RoutingConvergenceVerificationReport {
    pub schema_version: u32,
    pub scope: String,
    pub engine_version: String,
    pub input_kind: RoutingConvergenceVerificationInputKind,
    pub status: RoutingConvergenceVerificationStatus,
    pub routing_complete: bool,
    pub source_authenticity_verified: bool,
    pub native_kicad_drc_verified: bool,
    pub manufacturability_verified: bool,
    pub release_authorized: bool,
    pub built_in_dfm_profile: Option<String>,
    pub sources: RoutingConvergenceVerificationSources,
    pub convergence: RoutingConvergenceReport,
    pub validation: RoutingConvergenceVerificationChecks,
    pub binding_sha256: String,
}

#[derive(Serialize)]
struct BindingMaterial<'a> {
    schema_version: u32,
    scope: &'a str,
    engine_version: &'a str,
    input_kind: RoutingConvergenceVerificationInputKind,
    status: RoutingConvergenceVerificationStatus,
    routing_complete: bool,
    source_authenticity_verified: bool,
    native_kicad_drc_verified: bool,
    manufacturability_verified: bool,
    release_authorized: bool,
    built_in_dfm_profile: &'a Option<String>,
    sources: &'a RoutingConvergenceVerificationSources,
    convergence: &'a RoutingConvergenceReport,
    validation: &'a RoutingConvergenceVerificationChecks,
}

pub(crate) struct KicadRoutingVerificationSources<'a> {
    pub input: &'a [u8],
    pub routed_output: &'a [u8],
    pub retained_report: &'a [u8],
    pub project: Option<&'a [u8]>,
    pub rules_file: Option<&'a [u8]>,
    pub fab_profile: Option<&'a [u8]>,
    pub policy_pack: Option<&'a [u8]>,
    pub physical_profile: Option<&'a [u8]>,
}

pub(crate) fn verify_board_json_routing_convergence(
    input: &[u8],
    routed_output: &[u8],
    retained_report: &[u8],
    physical_profile: Option<&[u8]>,
) -> Result<RoutingConvergenceVerificationReport> {
    validate_aggregate_bytes(
        &[
            Some(input),
            Some(routed_output),
            Some(retained_report),
            physical_profile,
        ],
        MAX_BOARD_JSON_ROUTING_VERIFICATION_INPUT_BYTES,
    )?;
    let mut board = parse_board_source(input)?;
    if let Some(source) = physical_profile {
        let profile = parse_physical_profile_source(source)?;
        apply_physical_profile(&mut board, &profile)
            .map_err(anyhow::Error::msg)
            .context("applying captured physical profile")?;
    }
    let retained = decode_routing_convergence_report(retained_report)?;
    let fresh = verify_routing_convergence_report(&board, &retained)
        .map_err(anyhow::Error::msg)
        .context("freshly replaying retained routing convergence report")?;
    let expected_output = serde_json::to_string_pretty(&fresh.board)
        .context("rendering freshly selected routed Board JSON")?;
    if expected_output.as_bytes() != routed_output {
        bail!("routed Board JSON does not match the freshly selected convergence output");
    }
    build_verification_report(
        RoutingConvergenceVerificationInputKind::BoardJson,
        None,
        RoutingConvergenceVerificationSources {
            input: exact_identity(input),
            routed_output: exact_identity(routed_output),
            retained_report: exact_identity(retained_report),
            project: None,
            rules_file: None,
            fab_profile: None,
            policy_pack: None,
            physical_profile: physical_profile.map(exact_identity),
        },
        fresh.report,
    )
}

pub(crate) fn verify_kicad_routing_convergence(
    sources: KicadRoutingVerificationSources<'_>,
    rules: Rules,
    built_in_fab: Option<&str>,
) -> Result<RoutingConvergenceVerificationReport> {
    validate_aggregate_bytes(
        &[
            Some(sources.input),
            Some(sources.routed_output),
            Some(sources.retained_report),
            sources.project,
            sources.rules_file,
            sources.fab_profile,
            sources.policy_pack,
            sources.physical_profile,
        ],
        MAX_KICAD_ROUTING_VERIFICATION_INPUT_BYTES,
    )?;
    let selected_profiles = usize::from(built_in_fab.is_some())
        + usize::from(sources.fab_profile.is_some())
        + usize::from(sources.policy_pack.is_some())
        + usize::from(sources.physical_profile.is_some());
    if selected_profiles > 1 {
        bail!("routing convergence verification accepts only one DFM or physical profile source");
    }
    if rules.via_drill_nm >= rules.via_diameter_nm {
        bail!("via drill must be smaller than via diameter");
    }
    let input = decode_utf8(sources.input, "KiCad input board")?;
    let mut imported = import_kicad(input, rules)
        .map_err(anyhow::Error::msg)
        .context("importing captured KiCad input board")?;
    if let Some(project) = sources.project {
        reject_duplicate_json_keys(project).context("decoding captured KiCad project")?;
        apply_project_net_settings(&mut imported.board, decode_utf8(project, "KiCad project")?)
            .map_err(anyhow::Error::msg)
            .context("applying captured KiCad project")?;
    }
    if let Some(rules_file) = sources.rules_file {
        apply_custom_design_rules(
            &mut imported.board,
            decode_utf8(rules_file, "KiCad custom rules")?,
        )
        .map_err(anyhow::Error::msg)
        .context("applying captured KiCad custom rules")?;
    }

    let mut normalized_builtin = None;
    let profile: Option<DfmProfile> = if let Some(name) = built_in_fab {
        let profile = dfm_profile(name)
            .ok_or_else(|| anyhow::anyhow!("unknown built-in fabrication profile {name:?}"))?;
        normalized_builtin = Some(profile.id.clone());
        Some(profile)
    } else if let Some(source) = sources.fab_profile {
        reject_duplicate_json_keys(source).context("decoding captured external DFM profile")?;
        Some(
            parse_external_dfm_profile(decode_utf8(source, "external DFM profile")?)
                .map_err(anyhow::Error::msg)
                .context("validating captured external DFM profile")?,
        )
    } else if let Some(source) = sources.policy_pack {
        reject_duplicate_json_keys(source).context("decoding captured organization policy pack")?;
        Some(
            parse_policy_pack(decode_utf8(source, "organization policy pack")?)
                .map_err(anyhow::Error::msg)
                .context("validating captured organization policy pack")?
                .dfm_profile,
        )
    } else {
        None
    };
    if let Some(profile) = profile.as_ref() {
        apply_dfm_profile(&mut imported.board, profile);
    }
    if let Some(source) = sources.physical_profile {
        let profile = parse_physical_profile_source(source)?;
        apply_physical_profile(&mut imported.board, &profile)
            .map_err(anyhow::Error::msg)
            .context("applying captured physical profile")?;
    }

    let retained = decode_routing_convergence_report(sources.retained_report)?;
    let fresh = verify_routing_convergence_report(&imported.board, &retained)
        .map_err(anyhow::Error::msg)
        .context("freshly replaying retained KiCad routing convergence report")?;
    let expected_output = imported
        .write_routes(&fresh.board.routes)
        .map_err(anyhow::Error::msg)
        .context("rendering freshly selected routed KiCad board")?;
    if expected_output.as_bytes() != sources.routed_output {
        bail!("routed KiCad board does not match the freshly selected convergence output");
    }

    build_verification_report(
        RoutingConvergenceVerificationInputKind::KicadPcb,
        normalized_builtin,
        RoutingConvergenceVerificationSources {
            input: exact_identity(sources.input),
            routed_output: exact_identity(sources.routed_output),
            retained_report: exact_identity(sources.retained_report),
            project: sources.project.map(exact_identity),
            rules_file: sources.rules_file.map(exact_identity),
            fab_profile: sources.fab_profile.map(exact_identity),
            policy_pack: sources.policy_pack.map(exact_identity),
            physical_profile: sources.physical_profile.map(exact_identity),
        },
        fresh.report,
    )
}

fn parse_board_source(source: &[u8]) -> Result<Board> {
    reject_duplicate_json_keys(source).context("decoding captured Board JSON")?;
    parse_board_json(decode_utf8(source, "Board JSON")?)
        .map_err(anyhow::Error::msg)
        .context("validating captured Board JSON")
}

fn parse_physical_profile_source(source: &[u8]) -> Result<PhysicalConstraintProfile> {
    reject_duplicate_json_keys(source).context("decoding captured physical profile")?;
    parse_physical_profile(decode_utf8(source, "physical profile")?)
        .map_err(anyhow::Error::msg)
        .context("validating captured physical profile")
}

fn decode_utf8<'a>(source: &'a [u8], label: &str) -> Result<&'a str> {
    if source.is_empty() {
        bail!("{label} must not be empty");
    }
    std::str::from_utf8(source).with_context(|| format!("decoding {label} as UTF-8"))
}

fn validate_aggregate_bytes(inputs: &[Option<&[u8]>], maximum_bytes: u64) -> Result<()> {
    let total = inputs.iter().flatten().try_fold(0_u64, |total, source| {
        let bytes = u64::try_from(source.len()).map_err(|_| {
            anyhow::anyhow!("routing verification byte count cannot be represented")
        })?;
        total
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("routing verification aggregate byte count overflow"))
    })?;
    if total > maximum_bytes {
        bail!("routing verification inputs exceed the {maximum_bytes}-byte aggregate limit");
    }
    Ok(())
}

fn decode_routing_convergence_report(source: &[u8]) -> Result<RoutingConvergenceReport> {
    if source.is_empty() {
        bail!("retained routing convergence report must not be empty");
    }
    if source.len() as u64 > MAX_ROUTING_CONVERGENCE_REPORT_BYTES {
        bail!(
            "retained routing convergence report exceeds {MAX_ROUTING_CONVERGENCE_REPORT_BYTES} bytes"
        );
    }
    reject_duplicate_json_keys(source).context("decoding retained routing convergence report")?;
    let report: RoutingConvergenceReport =
        serde_json::from_slice(source).context("decoding retained routing convergence report")?;
    let canonical = render_routing_convergence_report(&report)
        .map_err(anyhow::Error::msg)
        .context("rendering retained routing convergence report")?;
    if canonical.as_bytes() != source {
        bail!("retained routing convergence report is not canonical JSON");
    }
    Ok(report)
}

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

fn build_verification_report(
    input_kind: RoutingConvergenceVerificationInputKind,
    built_in_dfm_profile: Option<String>,
    sources: RoutingConvergenceVerificationSources,
    convergence: RoutingConvergenceReport,
) -> Result<RoutingConvergenceVerificationReport> {
    let routing_complete = convergence.converged;
    let status = match convergence.status {
        RoutingConvergenceStatus::Converged => RoutingConvergenceVerificationStatus::Complete,
        RoutingConvergenceStatus::Partial => RoutingConvergenceVerificationStatus::Partial,
        RoutingConvergenceStatus::NoAdmissibleCandidate => {
            RoutingConvergenceVerificationStatus::NoAdmissibleCandidate
        }
    };
    let mut report = RoutingConvergenceVerificationReport {
        schema_version: 1,
        scope: "fresh_exact_routing_convergence_verification".into(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        input_kind,
        status,
        routing_complete,
        source_authenticity_verified: false,
        native_kicad_drc_verified: false,
        manufacturability_verified: false,
        release_authorized: false,
        built_in_dfm_profile,
        sources,
        convergence,
        validation: RoutingConvergenceVerificationChecks {
            source_closure_captured: true,
            retained_report_canonical: true,
            fresh_convergence_replayed: true,
            retained_report_exact: true,
            routed_output_exact: true,
            caller_inputs_unchanged: true,
        },
        binding_sha256: String::new(),
    };
    report.binding_sha256 = verification_binding_sha256(&report)?;
    validate_verification_report(&report)?;
    Ok(report)
}

fn verification_binding_sha256(report: &RoutingConvergenceVerificationReport) -> Result<String> {
    let material = BindingMaterial {
        schema_version: report.schema_version,
        scope: &report.scope,
        engine_version: &report.engine_version,
        input_kind: report.input_kind,
        status: report.status,
        routing_complete: report.routing_complete,
        source_authenticity_verified: report.source_authenticity_verified,
        native_kicad_drc_verified: report.native_kicad_drc_verified,
        manufacturability_verified: report.manufacturability_verified,
        release_authorized: report.release_authorized,
        built_in_dfm_profile: &report.built_in_dfm_profile,
        sources: &report.sources,
        convergence: &report.convergence,
        validation: &report.validation,
    };
    let canonical = serde_json::to_vec(&material)
        .context("serializing routing convergence verification binding")?;
    let mut digest = Sha256::new();
    digest.update(BINDING_DOMAIN);
    digest.update(canonical);
    Ok(hex::encode(digest.finalize()))
}

fn validate_verification_report(report: &RoutingConvergenceVerificationReport) -> Result<()> {
    if report.schema_version != 1 || report.scope != "fresh_exact_routing_convergence_verification"
    {
        bail!("routing convergence verification report header is invalid");
    }
    if report.engine_version != env!("CARGO_PKG_VERSION") {
        bail!("routing convergence verification engine version is invalid");
    }
    if report.source_authenticity_verified
        || report.native_kicad_drc_verified
        || report.manufacturability_verified
        || report.release_authorized
    {
        bail!("routing convergence verification contains unsupported authority claims");
    }
    if let Some(profile) = report.built_in_dfm_profile.as_deref()
        && (profile.is_empty()
            || profile.len() > 128
            || !profile
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        bail!("routing convergence verification built-in DFM profile is invalid");
    }
    for (identity, maximum, label) in [
        (&report.sources.input, MAX_ROUTING_SOURCE_BYTES, "input"),
        (
            &report.sources.routed_output,
            MAX_ROUTING_SOURCE_BYTES,
            "routed output",
        ),
        (
            &report.sources.retained_report,
            MAX_ROUTING_CONVERGENCE_REPORT_BYTES,
            "retained report",
        ),
    ] {
        validate_identity(identity, maximum, label)?;
    }
    for (identity, maximum, label) in [
        (
            report.sources.project.as_ref(),
            MAX_ROUTING_SOURCE_BYTES,
            "project",
        ),
        (
            report.sources.rules_file.as_ref(),
            MAX_ROUTING_SOURCE_BYTES,
            "rules file",
        ),
        (
            report.sources.fab_profile.as_ref(),
            MAX_DFM_PROFILE_TEXT_BYTES as u64,
            "DFM profile",
        ),
        (
            report.sources.policy_pack.as_ref(),
            MAX_ROUTING_POLICY_PACK_BYTES,
            "policy pack",
        ),
        (
            report.sources.physical_profile.as_ref(),
            MAX_ROUTING_PROFILE_BYTES,
            "physical profile",
        ),
    ] {
        if let Some(identity) = identity {
            validate_identity(identity, maximum, label)?;
        }
    }
    let expected_status = match report.convergence.status {
        RoutingConvergenceStatus::Converged => RoutingConvergenceVerificationStatus::Complete,
        RoutingConvergenceStatus::Partial => RoutingConvergenceVerificationStatus::Partial,
        RoutingConvergenceStatus::NoAdmissibleCandidate => {
            RoutingConvergenceVerificationStatus::NoAdmissibleCandidate
        }
    };
    if report.status != expected_status
        || report.routing_complete != report.convergence.converged
        || report.routing_complete
            != (report.convergence.final_metrics.unrouted_nets == 0
                && report.convergence.final_drc_violation_count == 0)
    {
        bail!("routing convergence verification decision is inconsistent");
    }
    if !report.validation.source_closure_captured
        || !report.validation.retained_report_canonical
        || !report.validation.fresh_convergence_replayed
        || !report.validation.retained_report_exact
        || !report.validation.routed_output_exact
        || !report.validation.caller_inputs_unchanged
    {
        bail!("routing convergence verification checks are incomplete");
    }
    if report.binding_sha256 != verification_binding_sha256(report)? {
        bail!("routing convergence verification binding SHA-256 is invalid");
    }
    Ok(())
}

fn validate_identity(
    identity: &ExactArtifactIdentity,
    maximum_bytes: u64,
    label: &str,
) -> Result<()> {
    if identity.bytes == 0 || identity.bytes > maximum_bytes {
        bail!("routing convergence verification {label} byte count is out of bounds");
    }
    if identity.sha256.len() != 64
        || !identity
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("routing convergence verification {label} SHA-256 is invalid");
    }
    Ok(())
}

pub(crate) fn render_routing_convergence_verification_report(
    report: &RoutingConvergenceVerificationReport,
) -> Result<Vec<u8>> {
    validate_verification_report(report)?;
    let mut rendered = serde_json::to_vec_pretty(report)
        .context("rendering routing convergence verification report")?;
    rendered.push(b'\n');
    if rendered.len() as u64 > MAX_ROUTING_CONVERGENCE_VERIFICATION_REPORT_BYTES {
        bail!(
            "routing convergence verification report exceeds {MAX_ROUTING_CONVERGENCE_VERIFICATION_REPORT_BYTES} bytes"
        );
    }
    Ok(rendered)
}

pub(crate) fn routing_convergence_verification_report_json_schema() -> Value {
    let mut convergence_schema = routing_convergence_report_json_schema();
    let convergence_required = convergence_schema
        .get_mut("required")
        .map(Value::take)
        .expect("routing convergence schema has required fields");
    let convergence_properties = convergence_schema
        .get_mut("properties")
        .map(Value::take)
        .expect("routing convergence schema has properties");
    let mut definitions = convergence_schema
        .get_mut("$defs")
        .map(Value::take)
        .and_then(|value| value.as_object().cloned())
        .expect("routing convergence schema has definitions");
    definitions.insert(
        "convergence_report".into(),
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": convergence_required,
            "properties": convergence_properties
        }),
    );
    for (name, maximum) in [
        ("source_identity", MAX_ROUTING_SOURCE_BYTES),
        (
            "retained_report_identity",
            MAX_ROUTING_CONVERGENCE_REPORT_BYTES,
        ),
        ("dfm_profile_identity", MAX_DFM_PROFILE_TEXT_BYTES as u64),
        ("policy_pack_identity", MAX_ROUTING_POLICY_PACK_BYTES),
        ("physical_profile_identity", MAX_ROUTING_PROFILE_BYTES),
    ] {
        definitions.insert(
            name.into(),
            json!({
                "type": "object", "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            }),
        );
    }
    let nullable_identity = |reference: &str| {
        json!({
            "anyOf": [
                {"type": "null"},
                {"$ref": reference}
            ]
        })
    };
    definitions.insert(
        "sources".into(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["input", "routed_output", "retained_report", "project", "rules_file", "fab_profile", "policy_pack", "physical_profile"],
            "properties": {
                "input": {"$ref": "#/$defs/source_identity"},
                "routed_output": {"$ref": "#/$defs/source_identity"},
                "retained_report": {"$ref": "#/$defs/retained_report_identity"},
                "project": nullable_identity("#/$defs/source_identity"),
                "rules_file": nullable_identity("#/$defs/source_identity"),
                "fab_profile": nullable_identity("#/$defs/dfm_profile_identity"),
                "policy_pack": nullable_identity("#/$defs/policy_pack_identity"),
                "physical_profile": nullable_identity("#/$defs/physical_profile_identity")
            }
        }),
    );
    definitions.insert(
        "validation".into(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["source_closure_captured", "retained_report_canonical", "fresh_convergence_replayed", "retained_report_exact", "routed_output_exact", "caller_inputs_unchanged"],
            "properties": {
                "source_closure_captured": {"const": true},
                "retained_report_canonical": {"const": true},
                "fresh_convergence_replayed": {"const": true},
                "retained_report_exact": {"const": true},
                "routed_output_exact": {"const": true},
                "caller_inputs_unchanged": {"const": true}
            }
        }),
    );
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/routing-convergence-verification-report-v1.json",
        "title": "pcbex fresh exact routing convergence verification report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "scope", "engine_version", "input_kind", "status", "routing_complete",
            "source_authenticity_verified", "native_kicad_drc_verified", "manufacturability_verified", "release_authorized",
            "built_in_dfm_profile", "sources", "convergence", "validation", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "scope": {"const": "fresh_exact_routing_convergence_verification"},
            "engine_version": {"type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$", "maxLength": 32},
            "input_kind": {"enum": ["board_json", "kicad_pcb"]},
            "status": {"enum": ["verified_complete", "verified_partial", "verified_no_admissible_candidate"]},
            "routing_complete": {"type": "boolean"},
            "source_authenticity_verified": {"const": false},
            "native_kicad_drc_verified": {"const": false},
            "manufacturability_verified": {"const": false},
            "release_authorized": {"const": false},
            "built_in_dfm_profile": {
                "anyOf": [
                    {"type": "null"},
                    {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"}
                ]
            },
            "sources": {"$ref": "#/$defs/sources"},
            "convergence": {"$ref": "#/$defs/convergence_report"},
            "validation": {"$ref": "#/$defs/validation"},
            "binding_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        },
        "$defs": Value::Object(definitions)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_schema_is_recursively_closed_and_bounded() {
        fn audit(value: &Value) {
            if value.get("type") == Some(&Value::String("object".into())) {
                assert_eq!(value.get("additionalProperties"), Some(&Value::Bool(false)));
            }
            if value.get("type") == Some(&Value::String("array".into())) {
                assert!(value.get("maxItems").is_some());
            }
            match value {
                Value::Array(values) => values.iter().for_each(audit),
                Value::Object(values) => values.values().for_each(audit),
                _ => {}
            }
        }
        let schema = routing_convergence_verification_report_json_schema();
        audit(&schema);
        assert_eq!(schema["additionalProperties"], false);
    }
}
