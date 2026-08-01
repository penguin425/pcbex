use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

pub const MANUFACTURING_FEEDBACK_SCHEMA_VERSION: u32 = 1;
pub const MANUFACTURING_FEEDBACK_COMPARISON_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manufacturer {
    pub id: String,
    pub process: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lot: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManufacturingDisposition {
    Accepted,
    AcceptedWithNotes,
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManufacturingSeverity {
    Info,
    Warning,
    Error,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManufacturingCategory {
    TraceWidth,
    Clearance,
    Drill,
    AnnularRing,
    SolderMask,
    Silkscreen,
    Impedance,
    Stackup,
    Panelization,
    Assembly,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManufacturingMeasurement {
    pub name: String,
    pub value: f64,
    pub unit: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManufacturingFinding {
    pub id: String,
    pub category: ManufacturingCategory,
    pub severity: ManufacturingSeverity,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measurement: Option<ManufacturingMeasurement>,
    pub evidence: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManufacturingFeedbackDeclaration {
    pub schema_version: u32,
    pub id: String,
    pub manufacturer: Manufacturer,
    pub received_on: String,
    pub board_sha256: String,
    pub disposition: ManufacturingDisposition,
    pub findings: Vec<ManufacturingFinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceDescriptor {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManufacturingFeedback {
    pub schema_version: u32,
    pub declaration: ManufacturingFeedbackDeclaration,
    pub analysis_manifest: EvidenceDescriptor,
    pub board: EvidenceDescriptor,
    pub artifacts: Vec<EvidenceDescriptor>,
    pub passed: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManufacturingFindingEscalation {
    pub id: String,
    pub baseline_severity: ManufacturingSeverity,
    pub current: ManufacturingFinding,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManufacturingFeedbackComparison {
    pub schema_version: u32,
    pub manufacturer_id: String,
    pub baseline_sha256: String,
    pub current_sha256: String,
    pub baseline_disposition: ManufacturingDisposition,
    pub current_disposition: ManufacturingDisposition,
    pub new_findings: Vec<ManufacturingFinding>,
    pub escalated_findings: Vec<ManufacturingFindingEscalation>,
    pub resolved_findings: Vec<ManufacturingFinding>,
    pub regression: bool,
}

pub fn parse_manufacturing_feedback_declaration(
    source: &str,
) -> Result<ManufacturingFeedbackDeclaration, String> {
    let declaration: ManufacturingFeedbackDeclaration = serde_json::from_str(source)
        .map_err(|error| format!("invalid manufacturing feedback declaration JSON: {error}"))?;
    validate_declaration(&declaration)?;
    Ok(declaration)
}

pub fn parse_manufacturing_feedback(source: &str) -> Result<ManufacturingFeedback, String> {
    let feedback: ManufacturingFeedback = serde_json::from_str(source)
        .map_err(|error| format!("invalid manufacturing feedback JSON: {error}"))?;
    validate_feedback(&feedback)?;
    Ok(feedback)
}

#[cfg(test)]
pub fn record_manufacturing_feedback(
    declaration: ManufacturingFeedbackDeclaration,
    analysis_manifest: (&str, &[u8]),
    board: (&str, &[u8]),
    artifacts: Vec<(&str, &[u8])>,
) -> Result<ManufacturingFeedback, String> {
    let board_descriptor = evidence_descriptor(board.0, board.1)?;
    let artifact_descriptors = artifacts
        .into_iter()
        .map(|(name, bytes)| evidence_descriptor(name, bytes))
        .collect::<Result<Vec<_>, _>>()?;
    bind_manufacturing_feedback(
        declaration,
        evidence_descriptor(analysis_manifest.0, analysis_manifest.1)?,
        board_descriptor,
        artifact_descriptors,
    )
}

pub fn bind_manufacturing_feedback(
    declaration: ManufacturingFeedbackDeclaration,
    analysis_manifest: EvidenceDescriptor,
    board: EvidenceDescriptor,
    artifacts: Vec<EvidenceDescriptor>,
) -> Result<ManufacturingFeedback, String> {
    validate_declaration(&declaration)?;
    if board.sha256 != declaration.board_sha256 {
        return Err("manufacturing feedback board SHA-256 does not match supplied board".into());
    }
    if artifacts.is_empty() {
        return Err("manufacturing feedback requires at least one evidence artifact".into());
    }
    let available = artifacts
        .iter()
        .map(|artifact| artifact.name.as_str())
        .collect::<HashSet<_>>();
    if available.len() != artifacts.len() {
        return Err("manufacturing feedback evidence artifact names must be unique".into());
    }
    for finding in &declaration.findings {
        for evidence in &finding.evidence {
            if !available.contains(evidence.as_str()) {
                return Err(format!(
                    "manufacturing finding {} references missing evidence artifact {:?}",
                    finding.id, evidence
                ));
            }
        }
    }
    let passed = declaration.disposition != ManufacturingDisposition::Rejected
        && !declaration
            .findings
            .iter()
            .any(|finding| finding.severity == ManufacturingSeverity::Error);
    let feedback = ManufacturingFeedback {
        schema_version: MANUFACTURING_FEEDBACK_SCHEMA_VERSION,
        declaration,
        analysis_manifest,
        board,
        artifacts,
        passed,
    };
    validate_feedback(&feedback)?;
    Ok(feedback)
}

pub fn verify_analysis_manifest_board(
    analysis_manifest: &[u8],
    board_sha256: &str,
) -> Result<(), String> {
    let manifest: Value = serde_json::from_slice(analysis_manifest)
        .map_err(|error| format!("invalid analyze-kicad run manifest JSON: {error}"))?;
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(1)
        || manifest.get("engine").and_then(Value::as_str) != Some("pcbex")
        || manifest.get("command").and_then(Value::as_str) != Some("analyze-kicad")
    {
        return Err("manufacturing feedback requires an analyze-kicad v1 run manifest".into());
    }
    let manifest_board_sha256 = manifest
        .pointer("/input/sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "analyze-kicad run manifest is missing input.sha256".to_string())?;
    validate_digest(
        manifest_board_sha256,
        "analyze-kicad run manifest board SHA-256",
    )?;
    if manifest_board_sha256 != board_sha256 {
        return Err("analyze-kicad run manifest does not describe the supplied board".into());
    }
    Ok(())
}

pub fn compare_manufacturing_feedback(
    baseline: &ManufacturingFeedback,
    current: &ManufacturingFeedback,
) -> Result<ManufacturingFeedbackComparison, String> {
    validate_feedback(baseline)?;
    validate_feedback(current)?;
    if baseline.declaration.manufacturer.id != current.declaration.manufacturer.id {
        return Err("manufacturing feedback comparison requires the same manufacturer id".into());
    }
    let baseline_by_id = baseline
        .declaration
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let current_by_id = current
        .declaration
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for (id, current_finding) in &current_by_id {
        if let Some(baseline_finding) = baseline_by_id.get(id)
            && baseline_finding.category != current_finding.category
        {
            return Err(format!(
                "manufacturing finding {id} maps to different categories"
            ));
        }
    }
    let mut new_findings = Vec::new();
    let mut escalated_findings = Vec::new();
    for (id, finding) in &current_by_id {
        match baseline_by_id.get(id) {
            None => new_findings.push((*finding).clone()),
            Some(previous) if finding.severity > previous.severity => {
                escalated_findings.push(ManufacturingFindingEscalation {
                    id: (*id).to_string(),
                    baseline_severity: previous.severity,
                    current: (*finding).clone(),
                });
            }
            _ => {}
        }
    }
    let resolved_findings = baseline_by_id
        .iter()
        .filter(|(id, _)| !current_by_id.contains_key(*id))
        .map(|(_, finding)| (*finding).clone())
        .collect::<Vec<_>>();
    let new_actionable = new_findings
        .iter()
        .any(|finding| finding.severity >= ManufacturingSeverity::Warning);
    let disposition_regressed = disposition_rank(current.declaration.disposition)
        > disposition_rank(baseline.declaration.disposition);
    let regression = disposition_regressed
        || !escalated_findings.is_empty()
        || new_actionable
        || (!current.passed && baseline.passed);
    Ok(ManufacturingFeedbackComparison {
        schema_version: MANUFACTURING_FEEDBACK_COMPARISON_SCHEMA_VERSION,
        manufacturer_id: current.declaration.manufacturer.id.clone(),
        baseline_sha256: normalized_sha256(baseline)?,
        current_sha256: normalized_sha256(current)?,
        baseline_disposition: baseline.declaration.disposition,
        current_disposition: current.declaration.disposition,
        new_findings,
        escalated_findings,
        resolved_findings,
        regression,
    })
}

pub fn manufacturing_feedback_declaration_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/manufacturing-feedback-declaration-v1.json",
        "title": "pcbex manufacturing feedback declaration",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "manufacturer", "received_on",
            "board_sha256", "disposition", "findings"
        ],
        "properties": {
            "schema_version": {"const": MANUFACTURING_FEEDBACK_SCHEMA_VERSION},
            "id": slug_schema(),
            "manufacturer": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "process"],
                "properties": {
                    "id": slug_schema(),
                    "process": {"type": "string", "minLength": 1, "maxLength": 256},
                    "lot": {"type": "string", "minLength": 1, "maxLength": 256}
                }
            },
            "received_on": {"type": "string", "format": "date"},
            "board_sha256": digest_schema(),
            "disposition": {
                "enum": ["accepted", "accepted_with_notes", "rejected"]
            },
            "findings": {
                "type": "array", "maxItems": 10000,
                "items": finding_schema()
            }
        }
    })
}

pub fn manufacturing_feedback_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/manufacturing-feedback-v1.json",
        "title": "pcbex bound manufacturing feedback",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "declaration", "analysis_manifest", "board",
            "artifacts", "passed"
        ],
        "properties": {
            "schema_version": {"const": MANUFACTURING_FEEDBACK_SCHEMA_VERSION},
            "declaration": manufacturing_feedback_declaration_json_schema(),
            "analysis_manifest": descriptor_schema(),
            "board": descriptor_schema(),
            "artifacts": {
                "type": "array", "minItems": 1, "maxItems": 1000,
                "items": descriptor_schema()
            },
            "passed": {"type": "boolean"}
        }
    })
}

pub fn manufacturing_feedback_comparison_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/manufacturing-feedback-comparison-v1.json",
        "title": "pcbex manufacturing feedback comparison",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "manufacturer_id", "baseline_sha256",
            "current_sha256", "baseline_disposition", "current_disposition",
            "new_findings", "escalated_findings", "resolved_findings", "regression"
        ],
        "properties": {
            "schema_version": {"const": MANUFACTURING_FEEDBACK_COMPARISON_SCHEMA_VERSION},
            "manufacturer_id": slug_schema(),
            "baseline_sha256": digest_schema(),
            "current_sha256": digest_schema(),
            "baseline_disposition": {
                "enum": ["accepted", "accepted_with_notes", "rejected"]
            },
            "current_disposition": {
                "enum": ["accepted", "accepted_with_notes", "rejected"]
            },
            "new_findings": {"type": "array", "items": finding_schema()},
            "escalated_findings": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["id", "baseline_severity", "current"],
                    "properties": {
                        "id": slug_schema(),
                        "baseline_severity": {"enum": ["info", "warning", "error"]},
                        "current": finding_schema()
                    }
                }
            },
            "resolved_findings": {"type": "array", "items": finding_schema()},
            "regression": {"type": "boolean"}
        }
    })
}

pub fn manufacturing_feedback_to_sarif(feedback: &ManufacturingFeedback) -> Value {
    let results = feedback
        .declaration
        .findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": format!("manufacturing_{}", category_name(finding.category)),
                "level": match finding.severity {
                    ManufacturingSeverity::Info => "note",
                    ManufacturingSeverity::Warning => "warning",
                    ManufacturingSeverity::Error => "error",
                },
                "message": {"text": finding.message},
                "properties": {
                    "findingId": finding.id,
                    "feedbackId": feedback.declaration.id,
                    "manufacturerId": feedback.declaration.manufacturer.id,
                    "evidence": finding.evidence
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pcbex manufacturing feedback",
                "informationUri": "https://github.com/penguin425/pcbex"
            }},
            "results": results
        }]
    })
}

pub fn render_manufacturing_feedback_summary(feedback: &ManufacturingFeedback) -> String {
    let errors = feedback
        .declaration
        .findings
        .iter()
        .filter(|finding| finding.severity == ManufacturingSeverity::Error)
        .count();
    let warnings = feedback
        .declaration
        .findings
        .iter()
        .filter(|finding| finding.severity == ManufacturingSeverity::Warning)
        .count();
    format!(
        "## Manufacturing feedback\n\n\
         - Feedback: `{}`\n\
         - Manufacturer: `{}`\n\
         - Disposition: `{}`\n\
         - Passed: `{}`\n\
         - Findings: {} error(s), {} warning(s), {} total\n\
         - Board SHA-256: `{}`\n",
        feedback.declaration.id,
        feedback.declaration.manufacturer.id,
        disposition_name(feedback.declaration.disposition),
        feedback.passed,
        errors,
        warnings,
        feedback.declaration.findings.len(),
        feedback.declaration.board_sha256
    )
}

pub fn manufacturing_feedback_comparison_to_sarif(
    comparison: &ManufacturingFeedbackComparison,
) -> Value {
    let mut results = comparison
        .new_findings
        .iter()
        .map(|finding| {
            json!({
                "ruleId": "new_manufacturing_finding",
                "level": match finding.severity {
                    ManufacturingSeverity::Info => "note",
                    ManufacturingSeverity::Warning => "warning",
                    ManufacturingSeverity::Error => "error",
                },
                "message": {"text": format!("new manufacturing finding {}: {}", finding.id, finding.message)}
            })
        })
        .collect::<Vec<_>>();
    results.extend(comparison.escalated_findings.iter().map(|finding| {
        json!({
            "ruleId": "manufacturing_finding_escalated",
            "level": if finding.current.severity == ManufacturingSeverity::Error {
                "error"
            } else {
                "warning"
            },
            "message": {"text": format!(
                "manufacturing finding {} escalated from {} to {}",
                finding.id,
                severity_name(finding.baseline_severity),
                severity_name(finding.current.severity)
            )}
        })
    }));
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "pcbex compare manufacturing feedback",
                "informationUri": "https://github.com/penguin425/pcbex"
            }},
            "results": results
        }]
    })
}

pub fn render_manufacturing_feedback_comparison_summary(
    comparison: &ManufacturingFeedbackComparison,
) -> String {
    format!(
        "## Manufacturing feedback comparison\n\n\
         - Manufacturer: `{}`\n\
         - Disposition: `{}` → `{}`\n\
         - Regression: `{}`\n\
         - New findings: {}\n\
         - Escalated findings: {}\n\
         - Resolved findings: {}\n",
        comparison.manufacturer_id,
        disposition_name(comparison.baseline_disposition),
        disposition_name(comparison.current_disposition),
        comparison.regression,
        comparison.new_findings.len(),
        comparison.escalated_findings.len(),
        comparison.resolved_findings.len()
    )
}

fn validate_declaration(declaration: &ManufacturingFeedbackDeclaration) -> Result<(), String> {
    if declaration.schema_version != MANUFACTURING_FEEDBACK_SCHEMA_VERSION {
        return Err(format!(
            "unsupported manufacturing feedback schema_version {}; expected {}",
            declaration.schema_version, MANUFACTURING_FEEDBACK_SCHEMA_VERSION
        ));
    }
    validate_slug("manufacturing feedback id", &declaration.id)?;
    validate_slug("manufacturer id", &declaration.manufacturer.id)?;
    validate_text(
        "manufacturing process",
        &declaration.manufacturer.process,
        256,
    )?;
    if let Some(lot) = &declaration.manufacturer.lot {
        validate_text("manufacturing lot", lot, 256)?;
    }
    validate_date(&declaration.received_on)?;
    validate_digest(
        &declaration.board_sha256,
        "manufacturing feedback board SHA-256",
    )?;
    if declaration.findings.len() > 10_000 {
        return Err("manufacturing feedback may contain at most 10000 findings".into());
    }
    let mut ids = HashSet::new();
    for finding in &declaration.findings {
        validate_slug("manufacturing finding id", &finding.id)?;
        if !ids.insert(&finding.id) {
            return Err(format!(
                "duplicate manufacturing finding id {:?}",
                finding.id
            ));
        }
        validate_text("manufacturing finding message", &finding.message, 4096)?;
        if finding.evidence.is_empty() || finding.evidence.len() > 100 {
            return Err(format!(
                "manufacturing finding {} must cite 1 to 100 evidence artifacts",
                finding.id
            ));
        }
        let mut evidence = HashSet::new();
        for name in &finding.evidence {
            validate_name(name, "manufacturing evidence name")?;
            if !evidence.insert(name) {
                return Err(format!(
                    "manufacturing finding {} cites duplicate evidence {:?}",
                    finding.id, name
                ));
            }
        }
        if let Some(measurement) = &finding.measurement {
            validate_text("manufacturing measurement name", &measurement.name, 256)?;
            validate_text("manufacturing measurement unit", &measurement.unit, 64)?;
            for (label, value) in [
                ("value", Some(measurement.value)),
                ("minimum", measurement.minimum),
                ("maximum", measurement.maximum),
            ] {
                if value.is_some_and(|value| !value.is_finite()) {
                    return Err(format!("manufacturing measurement {label} must be finite"));
                }
            }
            if let (Some(minimum), Some(maximum)) = (measurement.minimum, measurement.maximum)
                && minimum > maximum
            {
                return Err("manufacturing measurement minimum exceeds maximum".into());
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_feedback(feedback: &ManufacturingFeedback) -> Result<(), String> {
    if feedback.schema_version != MANUFACTURING_FEEDBACK_SCHEMA_VERSION {
        return Err(format!(
            "unsupported bound manufacturing feedback schema_version {}; expected {}",
            feedback.schema_version, MANUFACTURING_FEEDBACK_SCHEMA_VERSION
        ));
    }
    validate_declaration(&feedback.declaration)?;
    validate_descriptor(&feedback.analysis_manifest)?;
    if feedback.analysis_manifest.name != "run.json" {
        return Err("manufacturing feedback analysis manifest must be named run.json".into());
    }
    validate_descriptor(&feedback.board)?;
    if feedback.board.sha256 != feedback.declaration.board_sha256 {
        return Err("bound manufacturing feedback board digest does not match declaration".into());
    }
    if feedback.artifacts.is_empty() || feedback.artifacts.len() > 1000 {
        return Err("bound manufacturing feedback requires 1 to 1000 artifacts".into());
    }
    let mut names = HashSet::new();
    for artifact in &feedback.artifacts {
        validate_descriptor(artifact)?;
        if !names.insert(&artifact.name) {
            return Err("bound manufacturing feedback artifact names must be unique".into());
        }
    }
    for finding in &feedback.declaration.findings {
        for evidence in &finding.evidence {
            if !names.contains(evidence) {
                return Err(format!(
                    "manufacturing finding {} references missing evidence artifact {:?}",
                    finding.id, evidence
                ));
            }
        }
    }
    let expected_passed = feedback.declaration.disposition != ManufacturingDisposition::Rejected
        && !feedback
            .declaration
            .findings
            .iter()
            .any(|finding| finding.severity == ManufacturingSeverity::Error);
    if feedback.passed != expected_passed {
        return Err("manufacturing feedback pass state is inconsistent with findings".into());
    }
    Ok(())
}

pub fn evidence_descriptor(name: &str, bytes: &[u8]) -> Result<EvidenceDescriptor, String> {
    validate_name(name, "evidence artifact name")?;
    Ok(EvidenceDescriptor {
        name: name.into(),
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    })
}

fn validate_descriptor(descriptor: &EvidenceDescriptor) -> Result<(), String> {
    validate_name(&descriptor.name, "evidence artifact name")?;
    validate_digest(&descriptor.sha256, "evidence artifact SHA-256")
}

fn normalized_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes =
        serde_json::to_vec(value).map_err(|error| format!("serializing evidence: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn disposition_rank(value: ManufacturingDisposition) -> u8 {
    match value {
        ManufacturingDisposition::Accepted => 0,
        ManufacturingDisposition::AcceptedWithNotes => 1,
        ManufacturingDisposition::Rejected => 2,
    }
}

fn disposition_name(value: ManufacturingDisposition) -> &'static str {
    match value {
        ManufacturingDisposition::Accepted => "accepted",
        ManufacturingDisposition::AcceptedWithNotes => "accepted_with_notes",
        ManufacturingDisposition::Rejected => "rejected",
    }
}

fn severity_name(value: ManufacturingSeverity) -> &'static str {
    match value {
        ManufacturingSeverity::Info => "info",
        ManufacturingSeverity::Warning => "warning",
        ManufacturingSeverity::Error => "error",
    }
}

fn category_name(value: ManufacturingCategory) -> &'static str {
    match value {
        ManufacturingCategory::TraceWidth => "trace_width",
        ManufacturingCategory::Clearance => "clearance",
        ManufacturingCategory::Drill => "drill",
        ManufacturingCategory::AnnularRing => "annular_ring",
        ManufacturingCategory::SolderMask => "solder_mask",
        ManufacturingCategory::Silkscreen => "silkscreen",
        ManufacturingCategory::Impedance => "impedance",
        ManufacturingCategory::Stackup => "stackup",
        ManufacturingCategory::Panelization => "panelization",
        ManufacturingCategory::Assembly => "assembly",
        ManufacturingCategory::Other => "other",
    }
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit());
    if valid {
        Ok(())
    } else {
        Err(format!(
            "{label} {value:?} must match [a-z0-9][a-z0-9.-]{{0,127}}"
        ))
    }
}

fn validate_text(label: &str, value: &str, maximum: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum {
        Err(format!("{label} must contain 1 to {maximum} bytes"))
    } else {
        Ok(())
    }
}

fn validate_name(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 255
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        Err(format!(
            "{label} must be a portable basename containing 1 to 255 bytes"
        ))
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        ))
    }
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
        return Err(format!(
            "received_on {value:?} must be a valid YYYY-MM-DD date"
        ));
    }
    let parts = value
        .split('-')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| format!("received_on {value:?} must be a valid YYYY-MM-DD date"))?;
    let (year, month, day) = (parts[0], parts[1], parts[2]);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > days {
        Err(format!(
            "received_on {value:?} must be a valid YYYY-MM-DD date"
        ))
    } else {
        Ok(())
    }
}

fn slug_schema() -> Value {
    json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"})
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn descriptor_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "bytes", "sha256"],
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 255},
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": digest_schema()
        }
    })
}

fn finding_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["id", "category", "severity", "message", "evidence"],
        "properties": {
            "id": slug_schema(),
            "category": {
                "enum": [
                    "trace_width", "clearance", "drill", "annular_ring",
                    "solder_mask", "silkscreen", "impedance", "stackup",
                    "panelization", "assembly", "other"
                ]
            },
            "severity": {"enum": ["info", "warning", "error"]},
            "message": {"type": "string", "minLength": 1, "maxLength": 4096},
            "measurement": {
                "type": "object", "additionalProperties": false,
                "required": ["name", "value", "unit"],
                "properties": {
                    "name": {"type": "string", "minLength": 1, "maxLength": 256},
                    "value": {"type": "number"},
                    "unit": {"type": "string", "minLength": 1, "maxLength": 64},
                    "minimum": {"type": "number"},
                    "maximum": {"type": "number"}
                }
            },
            "evidence": {
                "type": "array", "minItems": 1, "maxItems": 100,
                "items": {"type": "string", "minLength": 1, "maxLength": 255}
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration() -> ManufacturingFeedbackDeclaration {
        parse_manufacturing_feedback_declaration(
            r#"{
                "schema_version": 1,
                "id": "fab-lot-42",
                "manufacturer": {
                    "id": "example-fab",
                    "process": "4-layer production",
                    "lot": "lot-42"
                },
                "received_on": "2026-07-29",
                "board_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "disposition": "accepted_with_notes",
                "findings": [{
                    "id": "mask-sliver",
                    "category": "solder_mask",
                    "severity": "warning",
                    "message": "Mask sliver was below the preferred process target.",
                    "measurement": {
                        "name": "minimum mask sliver",
                        "value": 0.08,
                        "unit": "mm",
                        "minimum": 0.10
                    },
                    "evidence": ["inspection.csv"]
                }]
            }"#,
        )
        .unwrap()
    }

    #[test]
    fn records_digest_bound_feedback() {
        let mut declaration = declaration();
        declaration.board_sha256 = hex::encode(Sha256::digest(b"board"));
        let feedback = record_manufacturing_feedback(
            declaration,
            ("run.json", b"manifest"),
            ("board.kicad_pcb", b"board"),
            vec![("inspection.csv", b"mask_sliver_mm\n0.08\n")],
        )
        .unwrap();
        assert!(feedback.passed);
        assert_eq!(feedback.artifacts[0].bytes, 20);
        assert!(parse_manufacturing_feedback(&serde_json::to_string(&feedback).unwrap()).is_ok());
    }

    #[test]
    fn rejects_unknown_fields_tampering_and_missing_evidence() {
        let mut value = serde_json::to_value(declaration()).unwrap();
        value["unknown"] = true.into();
        assert!(parse_manufacturing_feedback_declaration(&value.to_string()).is_err());

        let mut declaration = declaration();
        declaration.board_sha256 = hex::encode(Sha256::digest(b"other"));
        assert!(
            record_manufacturing_feedback(
                declaration,
                ("run.json", b"manifest"),
                ("board.kicad_pcb", b"board"),
                vec![("different.csv", b"data")],
            )
            .is_err()
        );
    }

    #[test]
    fn compares_new_escalated_and_resolved_findings() {
        let mut baseline_declaration = declaration();
        baseline_declaration.board_sha256 = hex::encode(Sha256::digest(b"baseline"));
        baseline_declaration.findings.push(ManufacturingFinding {
            id: "resolved".into(),
            category: ManufacturingCategory::Other,
            severity: ManufacturingSeverity::Warning,
            message: "old".into(),
            measurement: None,
            evidence: vec!["inspection.csv".into()],
        });
        let baseline = record_manufacturing_feedback(
            baseline_declaration,
            ("run.json", b"baseline manifest"),
            ("baseline.kicad_pcb", b"baseline"),
            vec![("inspection.csv", b"baseline")],
        )
        .unwrap();
        let mut current_declaration = declaration();
        current_declaration.board_sha256 = hex::encode(Sha256::digest(b"current"));
        current_declaration.findings[0].severity = ManufacturingSeverity::Error;
        current_declaration.findings.push(ManufacturingFinding {
            id: "new-drill".into(),
            category: ManufacturingCategory::Drill,
            severity: ManufacturingSeverity::Warning,
            message: "new".into(),
            measurement: None,
            evidence: vec!["inspection.csv".into()],
        });
        let current = record_manufacturing_feedback(
            current_declaration,
            ("run.json", b"current manifest"),
            ("current.kicad_pcb", b"current"),
            vec![("inspection.csv", b"current")],
        )
        .unwrap();
        let comparison = compare_manufacturing_feedback(&baseline, &current).unwrap();
        assert!(comparison.regression);
        assert_eq!(comparison.new_findings[0].id, "new-drill");
        assert_eq!(comparison.escalated_findings[0].id, "mask-sliver");
        assert_eq!(comparison.resolved_findings[0].id, "resolved");
    }
}
