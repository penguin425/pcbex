use crate::manufacturing_feedback::{
    EvidenceDescriptor, ManufacturingCategory, ManufacturingFeedback, ManufacturingFinding,
    ManufacturingSeverity, validate_feedback,
};
use crate::policy_pack::{OrganizationPolicyPack, validate_policy_pack};
use pcbex_core::ManufacturingRules;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const POLICY_RECOMMENDATION_SCHEMA_VERSION: u32 = 1;
const MAXIMUM_INPUTS: usize = 1_000;
const MAXIMUM_MINIMUM_OCCURRENCES: u32 = 100;
const MAXIMUM_DIMENSION_NM: i64 = 1_000_000_000_000;
const MAXIMUM_TOTAL_FINDINGS: usize = 10_000;
const MAXIMUM_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendedRule {
    #[serde(rename = "minimum_track_width_nm")]
    TrackWidth,
    #[serde(rename = "minimum_clearance_nm")]
    Clearance,
    #[serde(rename = "minimum_drill_nm")]
    Drill,
    #[serde(rename = "minimum_annular_ring_nm")]
    AnnularRing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationSkipReason {
    NotActionableSeverity,
    UnsupportedCategory,
    MissingMeasurement,
    MissingRequiredMinimum,
    UnsupportedMeasurementUnit,
    InvalidMeasurement,
    MeasurementDoesNotShowShortfall,
    NotStricterThanCurrentPolicy,
    InsufficientIndependentFeedback,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFeedbackReference {
    pub feedback_id: String,
    pub feedback_sha256: String,
    pub manufacturer_id: String,
    pub board_sha256: String,
    pub received_on: String,
    pub analysis_manifest_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecommendationSource {
    pub feedback_id: String,
    pub feedback_sha256: String,
    pub finding_id: String,
    pub category: ManufacturingCategory,
    pub severity: ManufacturingSeverity,
    pub measured_value_nm: i64,
    pub required_minimum_nm: i64,
    pub evidence: Vec<EvidenceDescriptor>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRuleRecommendation {
    pub rule: RecommendedRule,
    pub direction: String,
    pub current_value_nm: i64,
    pub recommended_value_nm: i64,
    pub independent_feedback_count: u32,
    pub sources: Vec<PolicyRecommendationSource>,
    pub rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkippedPolicyFinding {
    pub feedback_id: String,
    pub finding_id: String,
    pub category: ManufacturingCategory,
    pub reason: RecommendationSkipReason,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecommendationReport {
    pub schema_version: u32,
    pub status: String,
    pub requires_human_approval: bool,
    pub may_relax_constraints: bool,
    pub generated_on: String,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub policy_pack_sha256: String,
    pub dfm_profile_id: String,
    pub dfm_profile_revision: u32,
    pub minimum_occurrences: u32,
    pub feedback: Vec<PolicyFeedbackReference>,
    pub recommendations: Vec<PolicyRuleRecommendation>,
    pub skipped_findings: Vec<SkippedPolicyFinding>,
}

pub struct PolicyRecommendationInput<'a> {
    pub feedback: &'a ManufacturingFeedback,
    pub analysis_manifest: &'a [u8],
}

#[derive(Clone)]
struct Candidate {
    rule: RecommendedRule,
    source: PolicyRecommendationSource,
}

pub fn generate_policy_recommendations(
    policy_pack: &OrganizationPolicyPack,
    inputs: &[PolicyRecommendationInput<'_>],
    generated_on: &str,
    minimum_occurrences: u32,
) -> Result<PolicyRecommendationReport, String> {
    validate_policy_pack(policy_pack)?;
    validate_date(generated_on)?;
    if !(2..=MAXIMUM_MINIMUM_OCCURRENCES).contains(&minimum_occurrences) {
        return Err(format!(
            "minimum occurrences must be between 2 and {MAXIMUM_MINIMUM_OCCURRENCES}"
        ));
    }
    if inputs.is_empty() || inputs.len() > MAXIMUM_INPUTS {
        return Err(format!(
            "policy recommendations require 1 to {MAXIMUM_INPUTS} feedback inputs"
        ));
    }

    let policy_pack_sha256 = normalized_sha256(policy_pack)?;
    let expected_profile = serde_json::to_value(&policy_pack.dfm_profile)
        .map_err(|error| format!("serializing target DFM profile: {error}"))?;
    let mut feedback_ids = HashSet::new();
    let mut feedback_digests = HashSet::new();
    let mut feedback_references = Vec::with_capacity(inputs.len());
    let mut candidates = Vec::new();
    let mut skipped = Vec::new();
    let mut total_findings = 0_usize;

    for input in inputs {
        validate_feedback(input.feedback)?;
        total_findings = total_findings
            .checked_add(input.feedback.declaration.findings.len())
            .ok_or_else(|| "policy recommendation finding count overflowed".to_string())?;
        if total_findings > MAXIMUM_TOTAL_FINDINGS {
            return Err(format!(
                "policy recommendations accept at most {MAXIMUM_TOTAL_FINDINGS} total findings"
            ));
        }
        validate_bound_manifest(input.feedback, input.analysis_manifest, &expected_profile)?;
        if input.feedback.declaration.received_on.as_str() > generated_on {
            return Err(format!(
                "manufacturing feedback {} is dated after recommendation generation",
                input.feedback.declaration.id
            ));
        }
        let feedback_id = &input.feedback.declaration.id;
        let feedback_sha256 = normalized_sha256(input.feedback)?;
        if !feedback_ids.insert(feedback_id.clone()) {
            return Err(format!(
                "duplicate manufacturing feedback id {feedback_id:?}"
            ));
        }
        if !feedback_digests.insert(feedback_sha256.clone()) {
            return Err("duplicate normalized manufacturing feedback content".into());
        }
        feedback_references.push(PolicyFeedbackReference {
            feedback_id: feedback_id.clone(),
            feedback_sha256: feedback_sha256.clone(),
            manufacturer_id: input.feedback.declaration.manufacturer.id.clone(),
            board_sha256: input.feedback.declaration.board_sha256.clone(),
            received_on: input.feedback.declaration.received_on.clone(),
            analysis_manifest_sha256: input.feedback.analysis_manifest.sha256.clone(),
        });

        let artifacts = input
            .feedback
            .artifacts
            .iter()
            .map(|artifact| (artifact.name.as_str(), artifact))
            .collect::<HashMap<_, _>>();
        for finding in &input.feedback.declaration.findings {
            match recommendation_candidate(
                finding,
                feedback_id,
                &feedback_sha256,
                &artifacts,
                &policy_pack.dfm_profile.rules,
            ) {
                Ok(candidate) => candidates.push(candidate),
                Err(reason) => skipped.push(SkippedPolicyFinding {
                    feedback_id: feedback_id.clone(),
                    finding_id: finding.id.clone(),
                    category: finding.category,
                    reason,
                }),
            }
        }
    }

    feedback_references.sort_by(|left, right| left.feedback_id.cmp(&right.feedback_id));
    candidates.sort_by(|left, right| {
        left.rule.cmp(&right.rule).then_with(|| {
            (&left.source.feedback_id, &left.source.finding_id)
                .cmp(&(&right.source.feedback_id, &right.source.finding_id))
        })
    });
    let mut grouped = BTreeMap::<RecommendedRule, Vec<PolicyRecommendationSource>>::new();
    for candidate in candidates {
        grouped
            .entry(candidate.rule)
            .or_default()
            .push(candidate.source);
    }

    let mut recommendations = Vec::new();
    for (rule, sources) in grouped {
        let distinct_feedback = sources
            .iter()
            .map(|source| source.feedback_id.as_str())
            .collect::<HashSet<_>>()
            .len() as u32;
        if distinct_feedback < minimum_occurrences {
            skipped.extend(sources.into_iter().map(|source| SkippedPolicyFinding {
                feedback_id: source.feedback_id,
                finding_id: source.finding_id,
                category: source.category,
                reason: RecommendationSkipReason::InsufficientIndependentFeedback,
            }));
            continue;
        }
        let current_value_nm = current_rule_value(&policy_pack.dfm_profile.rules, rule);
        let recommended_value_nm = sources
            .iter()
            .map(|source| source.required_minimum_nm)
            .max()
            .expect("a grouped recommendation has at least one source");
        recommendations.push(PolicyRuleRecommendation {
            rule,
            direction: "tighten_minimum".into(),
            current_value_nm,
            recommended_value_nm,
            independent_feedback_count: distinct_feedback,
            rationale: format!(
                "Increase {} from {} nm to {} nm based on {} independently bound manufacturing feedback records.",
                rule_name(rule),
                current_value_nm,
                recommended_value_nm,
                distinct_feedback
            ),
            sources,
        });
    }
    skipped.sort_by(|left, right| {
        (&left.feedback_id, &left.finding_id).cmp(&(&right.feedback_id, &right.finding_id))
    });
    let report = PolicyRecommendationReport {
        schema_version: POLICY_RECOMMENDATION_SCHEMA_VERSION,
        status: "proposal_only".into(),
        requires_human_approval: true,
        may_relax_constraints: false,
        generated_on: generated_on.into(),
        policy_pack_id: policy_pack.id.clone(),
        policy_pack_revision: policy_pack.revision,
        policy_pack_sha256,
        dfm_profile_id: policy_pack.dfm_profile.id.clone(),
        dfm_profile_revision: policy_pack.dfm_profile.revision,
        minimum_occurrences,
        feedback: feedback_references,
        recommendations,
        skipped_findings: skipped,
    };
    validate_policy_recommendation_report(&report)?;
    Ok(report)
}

pub fn parse_policy_recommendation_report(
    source: &str,
) -> Result<PolicyRecommendationReport, String> {
    let report: PolicyRecommendationReport = serde_json::from_str(source)
        .map_err(|error| format!("invalid policy recommendation JSON: {error}"))?;
    validate_policy_recommendation_report(&report)?;
    Ok(report)
}

pub fn validate_policy_recommendation_report(
    report: &PolicyRecommendationReport,
) -> Result<(), String> {
    if report.schema_version != POLICY_RECOMMENDATION_SCHEMA_VERSION {
        return Err(format!(
            "unsupported policy recommendation schema_version {}; expected {}",
            report.schema_version, POLICY_RECOMMENDATION_SCHEMA_VERSION
        ));
    }
    if report.status != "proposal_only"
        || !report.requires_human_approval
        || report.may_relax_constraints
    {
        return Err("policy recommendation governance boundary is invalid".into());
    }
    validate_date(&report.generated_on)?;
    validate_slug("policy pack id", &report.policy_pack_id)?;
    validate_slug("DFM profile id", &report.dfm_profile_id)?;
    if report.policy_pack_revision == 0 || report.dfm_profile_revision == 0 {
        return Err("policy and DFM profile revisions must be greater than zero".into());
    }
    validate_digest(&report.policy_pack_sha256, "policy pack SHA-256")?;
    if !(2..=MAXIMUM_MINIMUM_OCCURRENCES).contains(&report.minimum_occurrences) {
        return Err("policy recommendation minimum occurrences is invalid".into());
    }
    if report.feedback.is_empty() || report.feedback.len() > MAXIMUM_INPUTS {
        return Err("policy recommendation feedback references are unbounded".into());
    }
    let mut feedback_ids = HashSet::new();
    let mut feedback_digests = HashSet::new();
    let mut previous_feedback = None;
    for feedback in &report.feedback {
        validate_slug("manufacturing feedback id", &feedback.feedback_id)?;
        validate_slug("manufacturer id", &feedback.manufacturer_id)?;
        validate_digest(&feedback.feedback_sha256, "manufacturing feedback SHA-256")?;
        validate_digest(&feedback.board_sha256, "manufacturing board SHA-256")?;
        validate_digest(
            &feedback.analysis_manifest_sha256,
            "analysis manifest SHA-256",
        )?;
        validate_date(&feedback.received_on)?;
        if feedback.received_on > report.generated_on {
            return Err("policy recommendation contains future manufacturing feedback".into());
        }
        if !feedback_ids.insert(feedback.feedback_id.as_str())
            || !feedback_digests.insert(feedback.feedback_sha256.as_str())
        {
            return Err("policy recommendation contains duplicate feedback".into());
        }
        if previous_feedback.is_some_and(|previous| previous >= feedback.feedback_id.as_str()) {
            return Err("policy recommendation feedback must be strictly ordered".into());
        }
        previous_feedback = Some(feedback.feedback_id.as_str());
    }

    let known_feedback = report
        .feedback
        .iter()
        .map(|feedback| {
            (
                feedback.feedback_id.as_str(),
                feedback.feedback_sha256.as_str(),
            )
        })
        .collect::<HashSet<_>>();
    let mut rules = HashSet::new();
    let mut previous_rule = None;
    let mut used_findings = HashSet::new();
    for recommendation in &report.recommendations {
        if recommendation.direction != "tighten_minimum"
            || recommendation.current_value_nm < 0
            || recommendation.recommended_value_nm <= recommendation.current_value_nm
            || recommendation.recommended_value_nm > MAXIMUM_DIMENSION_NM
        {
            return Err("policy recommendation may only tighten a minimum dimension".into());
        }
        if !rules.insert(recommendation.rule) {
            return Err("policy recommendation contains a duplicate rule".into());
        }
        if previous_rule.is_some_and(|previous| previous >= recommendation.rule) {
            return Err("policy recommendations must be strictly ordered by rule".into());
        }
        previous_rule = Some(recommendation.rule);
        if recommendation.sources.is_empty() || recommendation.sources.len() > 10_000 {
            return Err("policy recommendation sources are unbounded".into());
        }
        let distinct_feedback = recommendation
            .sources
            .iter()
            .map(|source| source.feedback_id.as_str())
            .collect::<HashSet<_>>();
        if distinct_feedback.len() as u32 != recommendation.independent_feedback_count
            || recommendation.independent_feedback_count < report.minimum_occurrences
        {
            return Err("policy recommendation has insufficient independent evidence".into());
        }
        let mut source_ids = HashSet::new();
        let mut previous_source = None;
        for source in &recommendation.sources {
            validate_slug("manufacturing finding id", &source.finding_id)?;
            if !known_feedback
                .contains(&(source.feedback_id.as_str(), source.feedback_sha256.as_str()))
            {
                return Err("policy recommendation source references unknown feedback".into());
            }
            if !source_ids.insert((&source.feedback_id, &source.finding_id)) {
                return Err("policy recommendation contains a duplicate source".into());
            }
            if !used_findings.insert((source.feedback_id.as_str(), source.finding_id.as_str())) {
                return Err("manufacturing finding appears more than once in the report".into());
            }
            let source_identity = (source.feedback_id.as_str(), source.finding_id.as_str());
            if previous_source.is_some_and(|previous| previous >= source_identity) {
                return Err("policy recommendation sources must be strictly ordered".into());
            }
            previous_source = Some(source_identity);
            if source.required_minimum_nm <= recommendation.current_value_nm
                || source.required_minimum_nm > recommendation.recommended_value_nm
                || source.measured_value_nm >= source.required_minimum_nm
                || source.severity < ManufacturingSeverity::Warning
                || category_rule(source.category) != Some(recommendation.rule)
                || source.evidence.is_empty()
                || source.evidence.len() > 100
            {
                return Err("policy recommendation source is inconsistent".into());
            }
            validate_evidence(&source.evidence)?;
        }
        if recommendation
            .sources
            .iter()
            .map(|source| source.required_minimum_nm)
            .max()
            != Some(recommendation.recommended_value_nm)
        {
            return Err("recommended policy value does not match its evidence".into());
        }
        if recommendation.rationale.trim().is_empty() || recommendation.rationale.len() > 1024 {
            return Err("policy recommendation rationale is invalid".into());
        }
    }
    let mut skipped_ids = HashSet::new();
    let mut previous_skipped = None;
    for skipped in &report.skipped_findings {
        validate_slug("skipped manufacturing finding id", &skipped.finding_id)?;
        if !feedback_ids.contains(skipped.feedback_id.as_str())
            || !skipped_ids.insert((&skipped.feedback_id, &skipped.finding_id))
            || !used_findings.insert((skipped.feedback_id.as_str(), skipped.finding_id.as_str()))
        {
            return Err(
                "skipped policy finding is duplicate or references unknown feedback".into(),
            );
        }
        let skipped_identity = (skipped.feedback_id.as_str(), skipped.finding_id.as_str());
        if previous_skipped.is_some_and(|previous| previous >= skipped_identity) {
            return Err("skipped policy findings must be strictly ordered".into());
        }
        previous_skipped = Some(skipped_identity);
    }
    Ok(())
}

pub fn policy_recommendation_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let slug = json!({
        "type": "string",
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    });
    let evidence = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "bytes", "sha256"],
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": 255},
            "bytes": {"type": "integer", "minimum": 0},
            "sha256": digest
        }
    });
    let category = json!({
        "enum": [
            "trace_width", "clearance", "drill", "annular_ring",
            "solder_mask", "silkscreen", "impedance", "stackup",
            "panelization", "assembly", "other"
        ]
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/policy-recommendation-v1.json",
        "title": "pcbex governed manufacturing policy recommendation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "requires_human_approval",
            "may_relax_constraints", "generated_on", "policy_pack_id",
            "policy_pack_revision", "policy_pack_sha256", "dfm_profile_id",
            "dfm_profile_revision", "minimum_occurrences", "feedback",
            "recommendations", "skipped_findings"
        ],
        "properties": {
            "schema_version": {"const": POLICY_RECOMMENDATION_SCHEMA_VERSION},
            "status": {"const": "proposal_only"},
            "requires_human_approval": {"const": true},
            "may_relax_constraints": {"const": false},
            "generated_on": {"type": "string", "format": "date"},
            "policy_pack_id": slug,
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "policy_pack_sha256": digest,
            "dfm_profile_id": slug,
            "dfm_profile_revision": {"type": "integer", "minimum": 1},
            "minimum_occurrences": {
                "type": "integer", "minimum": 2,
                "maximum": MAXIMUM_MINIMUM_OCCURRENCES
            },
            "feedback": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_INPUTS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "feedback_id", "feedback_sha256", "manufacturer_id",
                        "board_sha256", "received_on", "analysis_manifest_sha256"
                    ],
                    "properties": {
                        "feedback_id": slug,
                        "feedback_sha256": digest,
                        "manufacturer_id": slug,
                        "board_sha256": digest,
                        "received_on": {"type": "string", "format": "date"},
                        "analysis_manifest_sha256": digest
                    }
                }
            },
            "recommendations": {
                "type": "array", "maxItems": 4,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": [
                        "rule", "direction", "current_value_nm",
                        "recommended_value_nm", "independent_feedback_count",
                        "sources", "rationale"
                    ],
                    "properties": {
                        "rule": {"enum": [
                            "minimum_track_width_nm", "minimum_clearance_nm",
                            "minimum_drill_nm", "minimum_annular_ring_nm"
                        ]},
                        "direction": {"const": "tighten_minimum"},
                        "current_value_nm": {
                            "type": "integer", "minimum": 0,
                            "maximum": MAXIMUM_DIMENSION_NM
                        },
                        "recommended_value_nm": {
                            "type": "integer", "minimum": 1,
                            "maximum": MAXIMUM_DIMENSION_NM
                        },
                        "independent_feedback_count": {
                            "type": "integer", "minimum": 2
                        },
                        "sources": {
                            "type": "array", "minItems": 1, "maxItems": 10000,
                            "items": {
                                "type": "object", "additionalProperties": false,
                                "required": [
                                    "feedback_id", "feedback_sha256", "finding_id",
                                    "category", "severity", "measured_value_nm",
                                    "required_minimum_nm", "evidence"
                                ],
                                "properties": {
                                    "feedback_id": slug,
                                    "feedback_sha256": digest,
                                    "finding_id": slug,
                                    "category": category,
                                    "severity": {"enum": ["info", "warning", "error"]},
                                    "measured_value_nm": {
                                        "type": "integer",
                                        "minimum": -MAXIMUM_DIMENSION_NM,
                                        "maximum": MAXIMUM_DIMENSION_NM
                                    },
                                    "required_minimum_nm": {
                                        "type": "integer", "minimum": 1,
                                        "maximum": MAXIMUM_DIMENSION_NM
                                    },
                                    "evidence": {
                                        "type": "array", "minItems": 1, "maxItems": 100,
                                        "items": evidence
                                    }
                                }
                            }
                        },
                        "rationale": {
                            "type": "string", "minLength": 1, "maxLength": 1024
                        }
                    }
                }
            },
            "skipped_findings": {
                "type": "array", "maxItems": 10000,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["feedback_id", "finding_id", "category", "reason"],
                    "properties": {
                        "feedback_id": slug,
                        "finding_id": slug,
                        "category": category,
                        "reason": {"enum": [
                            "not_actionable_severity", "unsupported_category",
                            "missing_measurement", "missing_required_minimum",
                            "unsupported_measurement_unit", "invalid_measurement",
                            "measurement_does_not_show_shortfall",
                            "not_stricter_than_current_policy",
                            "insufficient_independent_feedback"
                        ]}
                    }
                }
            }
        }
    })
}

pub fn render_policy_recommendation_summary(report: &PolicyRecommendationReport) -> String {
    let mut markdown = format!(
        "# Manufacturing policy recommendations\n\n\
         - Status: proposal only\n\
         - Human approval required: yes\n\
         - Target policy pack: `{}` revision {}\n\
         - Target DFM profile: `{}` revision {}\n\
         - Bound feedback records: {}\n\
         - Minimum independent occurrences: {}\n\
         - Recommendations: {}\n\
         - Findings requiring no automatic proposal: {}\n\n",
        report.policy_pack_id,
        report.policy_pack_revision,
        report.dfm_profile_id,
        report.dfm_profile_revision,
        report.feedback.len(),
        report.minimum_occurrences,
        report.recommendations.len(),
        report.skipped_findings.len()
    );
    if report.recommendations.is_empty() {
        markdown.push_str("No policy change met the governed evidence threshold.\n");
    } else {
        markdown.push_str("| Rule | Current | Recommended | Independent feedback |\n");
        markdown.push_str("| --- | ---: | ---: | ---: |\n");
        for recommendation in &report.recommendations {
            markdown.push_str(&format!(
                "| `{}` | {} nm | {} nm | {} |\n",
                rule_name(recommendation.rule),
                recommendation.current_value_nm,
                recommendation.recommended_value_nm,
                recommendation.independent_feedback_count
            ));
        }
    }
    markdown
}

fn recommendation_candidate(
    finding: &ManufacturingFinding,
    feedback_id: &str,
    feedback_sha256: &str,
    artifacts: &HashMap<&str, &EvidenceDescriptor>,
    rules: &ManufacturingRules,
) -> Result<Candidate, RecommendationSkipReason> {
    if finding.severity < ManufacturingSeverity::Warning {
        return Err(RecommendationSkipReason::NotActionableSeverity);
    }
    let rule =
        category_rule(finding.category).ok_or(RecommendationSkipReason::UnsupportedCategory)?;
    let measurement = finding
        .measurement
        .as_ref()
        .ok_or(RecommendationSkipReason::MissingMeasurement)?;
    let required = measurement
        .minimum
        .ok_or(RecommendationSkipReason::MissingRequiredMinimum)?;
    let multiplier = unit_multiplier(&measurement.unit)
        .ok_or(RecommendationSkipReason::UnsupportedMeasurementUnit)?;
    let measured_value_nm = measurement_to_nm(measurement.value, multiplier, false)
        .ok_or(RecommendationSkipReason::InvalidMeasurement)?;
    let required_minimum_nm = measurement_to_nm(required, multiplier, true)
        .ok_or(RecommendationSkipReason::InvalidMeasurement)?;
    if measured_value_nm >= required_minimum_nm {
        return Err(RecommendationSkipReason::MeasurementDoesNotShowShortfall);
    }
    if required_minimum_nm <= current_rule_value(rules, rule) {
        return Err(RecommendationSkipReason::NotStricterThanCurrentPolicy);
    }
    let mut evidence = finding
        .evidence
        .iter()
        .map(|name| {
            artifacts
                .get(name.as_str())
                .map(|descriptor| (*descriptor).clone())
                .ok_or(RecommendationSkipReason::InvalidMeasurement)
        })
        .collect::<Result<Vec<_>, _>>()?;
    evidence.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(Candidate {
        rule,
        source: PolicyRecommendationSource {
            feedback_id: feedback_id.into(),
            feedback_sha256: feedback_sha256.into(),
            finding_id: finding.id.clone(),
            category: finding.category,
            severity: finding.severity,
            measured_value_nm,
            required_minimum_nm,
            evidence,
        },
    })
}

fn validate_bound_manifest(
    feedback: &ManufacturingFeedback,
    manifest_bytes: &[u8],
    expected_profile: &Value,
) -> Result<(), String> {
    if manifest_bytes.len() as u64 != feedback.analysis_manifest.bytes
        || manifest_bytes.len() > MAXIMUM_MANIFEST_BYTES
        || hex::encode(Sha256::digest(manifest_bytes)) != feedback.analysis_manifest.sha256
    {
        return Err(format!(
            "analysis manifest does not match manufacturing feedback {}",
            feedback.declaration.id
        ));
    }
    let manifest: Value = serde_json::from_slice(manifest_bytes)
        .map_err(|error| format!("invalid bound analysis manifest JSON: {error}"))?;
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(1)
        || manifest.get("engine").and_then(Value::as_str) != Some("pcbex")
        || manifest.get("command").and_then(Value::as_str) != Some("analyze-kicad")
        || manifest.pointer("/input/sha256").and_then(Value::as_str)
            != Some(feedback.declaration.board_sha256.as_str())
    {
        return Err("bound analysis manifest identity does not match feedback".into());
    }
    if manifest.pointer("/configuration/dfm_profile") != Some(expected_profile) {
        return Err(format!(
            "manufacturing feedback {} was not analyzed with the target DFM profile",
            feedback.declaration.id
        ));
    }
    Ok(())
}

fn validate_evidence(evidence: &[EvidenceDescriptor]) -> Result<(), String> {
    let mut names = HashSet::new();
    let mut previous = None;
    for descriptor in evidence {
        if descriptor.name.is_empty()
            || descriptor.name.len() > 255
            || descriptor.name.contains(['/', '\\'])
            || !names.insert(&descriptor.name)
        {
            return Err("policy recommendation contains invalid evidence descriptors".into());
        }
        if previous.is_some_and(|previous| previous >= descriptor.name.as_str()) {
            return Err("policy recommendation evidence must be strictly ordered".into());
        }
        previous = Some(descriptor.name.as_str());
        validate_digest(&descriptor.sha256, "evidence SHA-256")?;
    }
    Ok(())
}

fn category_rule(category: ManufacturingCategory) -> Option<RecommendedRule> {
    match category {
        ManufacturingCategory::TraceWidth => Some(RecommendedRule::TrackWidth),
        ManufacturingCategory::Clearance => Some(RecommendedRule::Clearance),
        ManufacturingCategory::Drill => Some(RecommendedRule::Drill),
        ManufacturingCategory::AnnularRing => Some(RecommendedRule::AnnularRing),
        _ => None,
    }
}

fn current_rule_value(rules: &ManufacturingRules, rule: RecommendedRule) -> i64 {
    match rule {
        RecommendedRule::TrackWidth => rules.minimum_track_width_nm,
        RecommendedRule::Clearance => rules.minimum_clearance_nm,
        RecommendedRule::Drill => rules.minimum_drill_nm,
        RecommendedRule::AnnularRing => rules.minimum_annular_ring_nm,
    }
}

fn rule_name(rule: RecommendedRule) -> &'static str {
    match rule {
        RecommendedRule::TrackWidth => "minimum_track_width_nm",
        RecommendedRule::Clearance => "minimum_clearance_nm",
        RecommendedRule::Drill => "minimum_drill_nm",
        RecommendedRule::AnnularRing => "minimum_annular_ring_nm",
    }
}

fn unit_multiplier(unit: &str) -> Option<f64> {
    match unit.trim() {
        "nm" => Some(1.0),
        "um" | "µm" => Some(1_000.0),
        "mm" => Some(1_000_000.0),
        _ => None,
    }
}

fn measurement_to_nm(value: f64, multiplier: f64, round_up: bool) -> Option<i64> {
    let scaled = value * multiplier;
    if !scaled.is_finite() || scaled < 0.0 || scaled > MAXIMUM_DIMENSION_NM as f64 {
        return None;
    }
    let rounded = if round_up {
        scaled.ceil()
    } else {
        scaled.round()
    };
    let value = rounded as i64;
    (!round_up || value > 0).then_some(value)
}

fn normalized_sha256<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing policy recommendation evidence: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        Err(format!("{label} is not a valid stable identifier"))
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
    let parts = value
        .split('-')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "date must use YYYY-MM-DD".to_string())?;
    if parts.len() != 3 || value.len() != 10 {
        return Err("date must use YYYY-MM-DD".into());
    }
    let (year, month, day) = (parts[0], parts[1], parts[2]);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    };
    if year == 0 || day == 0 || day > maximum {
        Err("date must use a real YYYY-MM-DD calendar date".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manufacturing_feedback::{
        Manufacturer, ManufacturingDisposition, ManufacturingFeedbackDeclaration,
        bind_manufacturing_feedback, evidence_descriptor,
    };
    use crate::policy_pack::parse_policy_pack;

    fn pack() -> OrganizationPolicyPack {
        parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap()
    }

    fn input(
        id: &str,
        finding: ManufacturingFinding,
        pack: &OrganizationPolicyPack,
    ) -> (ManufacturingFeedback, Vec<u8>) {
        let board_sha256 = "a".repeat(64);
        let manifest = serde_json::to_vec(&json!({
            "schema_version": 1,
            "engine": "pcbex",
            "command": "analyze-kicad",
            "input": {"sha256": board_sha256},
            "configuration": {"dfm_profile": pack.dfm_profile}
        }))
        .unwrap();
        let feedback = bind_manufacturing_feedback(
            ManufacturingFeedbackDeclaration {
                schema_version: 1,
                id: id.into(),
                manufacturer: Manufacturer {
                    id: "example-fab".into(),
                    process: "production".into(),
                    lot: Some(id.into()),
                },
                received_on: "2026-07-28".into(),
                board_sha256,
                disposition: ManufacturingDisposition::AcceptedWithNotes,
                findings: vec![finding],
            },
            evidence_descriptor("run.json", &manifest).unwrap(),
            EvidenceDescriptor {
                name: "board.kicad_pcb".into(),
                bytes: 1,
                sha256: "a".repeat(64),
            },
            vec![evidence_descriptor("inspection.csv", b"result").unwrap()],
        )
        .unwrap();
        (feedback, manifest)
    }

    fn clearance_finding(id: &str, minimum: f64) -> ManufacturingFinding {
        ManufacturingFinding {
            id: id.into(),
            category: ManufacturingCategory::Clearance,
            severity: ManufacturingSeverity::Warning,
            message: "clearance below process target".into(),
            measurement: Some(crate::manufacturing_feedback::ManufacturingMeasurement {
                name: "clearance".into(),
                value: minimum - 0.01,
                unit: "mm".into(),
                minimum: Some(minimum),
                maximum: None,
            }),
            evidence: vec!["inspection.csv".into()],
        }
    }

    #[test]
    fn proposes_only_repeated_tightening_bound_to_the_exact_profile() {
        let pack = pack();
        let (first, first_manifest) =
            input("lot-one", clearance_finding("clearance-one", 0.14), &pack);
        let (second, second_manifest) =
            input("lot-two", clearance_finding("clearance-two", 0.15), &pack);
        let report = generate_policy_recommendations(
            &pack,
            &[
                PolicyRecommendationInput {
                    feedback: &first,
                    analysis_manifest: &first_manifest,
                },
                PolicyRecommendationInput {
                    feedback: &second,
                    analysis_manifest: &second_manifest,
                },
            ],
            "2026-07-29",
            2,
        )
        .unwrap();
        assert_eq!(report.recommendations.len(), 1);
        assert_eq!(report.recommendations[0].current_value_nm, 125_000);
        assert_eq!(report.recommendations[0].recommended_value_nm, 150_000);
        assert!(report.requires_human_approval);
        assert!(!report.may_relax_constraints);
        assert!(
            parse_policy_recommendation_report(&serde_json::to_string(&report).unwrap()).is_ok()
        );
    }

    #[test]
    fn retains_unsupported_and_insufficient_findings_without_proposing() {
        let pack = pack();
        let (single, manifest) = input("lot-one", clearance_finding("clearance-one", 0.14), &pack);
        let report = generate_policy_recommendations(
            &pack,
            &[PolicyRecommendationInput {
                feedback: &single,
                analysis_manifest: &manifest,
            }],
            "2026-07-29",
            2,
        )
        .unwrap();
        assert!(report.recommendations.is_empty());
        assert_eq!(
            report.skipped_findings[0].reason,
            RecommendationSkipReason::InsufficientIndependentFeedback
        );
    }

    #[test]
    fn rejects_manifest_tampering_profile_mismatch_and_governance_changes() {
        let pack = pack();
        let (feedback, manifest) =
            input("lot-one", clearance_finding("clearance-one", 0.14), &pack);
        assert!(
            generate_policy_recommendations(
                &pack,
                &[PolicyRecommendationInput {
                    feedback: &feedback,
                    analysis_manifest: b"{}",
                }],
                "2026-07-29",
                2,
            )
            .is_err()
        );
        let mut other_pack = pack.clone();
        other_pack.dfm_profile.rules.minimum_clearance_nm += 1;
        assert!(
            generate_policy_recommendations(
                &other_pack,
                &[PolicyRecommendationInput {
                    feedback: &feedback,
                    analysis_manifest: &manifest,
                }],
                "2026-07-29",
                2,
            )
            .is_err()
        );
        let mut report = PolicyRecommendationReport {
            schema_version: 1,
            status: "proposal_only".into(),
            requires_human_approval: false,
            may_relax_constraints: false,
            generated_on: "2026-07-29".into(),
            policy_pack_id: pack.id,
            policy_pack_revision: pack.revision,
            policy_pack_sha256: "a".repeat(64),
            dfm_profile_id: pack.dfm_profile.id,
            dfm_profile_revision: pack.dfm_profile.revision,
            minimum_occurrences: 2,
            feedback: vec![],
            recommendations: vec![],
            skipped_findings: vec![],
        };
        assert!(validate_policy_recommendation_report(&report).is_err());
        report.requires_human_approval = true;
        report.may_relax_constraints = true;
        assert!(validate_policy_recommendation_report(&report).is_err());
    }

    #[test]
    fn schema_closes_the_governance_and_source_objects() {
        let schema = policy_recommendation_json_schema();
        assert_eq!(
            schema["properties"]["requires_human_approval"]["const"],
            true
        );
        assert_eq!(
            schema["properties"]["may_relax_constraints"]["const"],
            false
        );
        assert_eq!(
            schema["properties"]["recommendations"]["items"]["additionalProperties"],
            false
        );
        assert_eq!(
            schema["properties"]["recommendations"]["items"]["properties"]["sources"]["items"]["additionalProperties"],
            false
        );
    }
}
