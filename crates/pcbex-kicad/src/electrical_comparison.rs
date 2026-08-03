use super::{
    ElectricalFinding, ElectricalFindingCounts, ElectricalReview, ElectricalSeverity,
    is_electrical_safety_floor_rule,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_FINDINGS: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalReviewIdentity {
    pub review_sha256: String,
    pub schematic_sha256: String,
    pub policy_sha256: String,
    pub policy_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalFindingSummary {
    pub id: String,
    pub rule: String,
    pub severity: ElectricalSeverity,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalSeverityChange {
    pub id: String,
    pub rule: String,
    pub baseline_severity: ElectricalSeverity,
    pub current_severity: ElectricalSeverity,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalComparisonCounts {
    pub new_errors: usize,
    pub new_warnings: usize,
    pub new_info: usize,
    pub resolved_errors: usize,
    pub resolved_warnings: usize,
    pub resolved_info: usize,
    pub severity_changes: usize,
    pub escalated_errors: usize,
    pub unchanged: usize,
    pub error_regressions: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ElectricalReviewComparison {
    pub schema_version: u32,
    pub baseline: ElectricalReviewIdentity,
    pub current: ElectricalReviewIdentity,
    pub passed: bool,
    pub counts: ElectricalComparisonCounts,
    pub new_findings: Vec<ElectricalFindingSummary>,
    pub resolved_findings: Vec<ElectricalFindingSummary>,
    pub severity_changes: Vec<ElectricalSeverityChange>,
}

pub fn compare_electrical_reviews(
    baseline: &ElectricalReview,
    current: &ElectricalReview,
) -> Result<ElectricalReviewComparison, String> {
    validate_review(baseline, "baseline")?;
    validate_review(current, "current")?;

    let baseline_by_id = baseline
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    let current_by_id = current
        .findings
        .iter()
        .map(|finding| (finding.id.as_str(), finding))
        .collect::<BTreeMap<_, _>>();
    for (id, current_finding) in &current_by_id {
        if let Some(baseline_finding) = baseline_by_id.get(id)
            && baseline_finding.rule != current_finding.rule
        {
            return Err(format!(
                "finding {id} maps to different rules in baseline and current reviews"
            ));
        }
    }

    let new_findings = current_by_id
        .iter()
        .filter(|(id, _)| !baseline_by_id.contains_key(**id))
        .map(|(_, finding)| finding_summary(finding))
        .collect::<Vec<_>>();
    let resolved_findings = baseline_by_id
        .iter()
        .filter(|(id, _)| !current_by_id.contains_key(**id))
        .map(|(_, finding)| finding_summary(finding))
        .collect::<Vec<_>>();
    let severity_changes = current_by_id
        .iter()
        .filter_map(|(id, current_finding)| {
            let baseline_finding = baseline_by_id.get(id)?;
            (baseline_finding.severity != current_finding.severity).then(|| {
                ElectricalSeverityChange {
                    id: (*id).to_string(),
                    rule: current_finding.rule.clone(),
                    baseline_severity: baseline_finding.severity,
                    current_severity: current_finding.severity,
                }
            })
        })
        .collect::<Vec<_>>();

    let counts = ElectricalComparisonCounts {
        new_errors: severity_count(&new_findings, ElectricalSeverity::Error),
        new_warnings: severity_count(&new_findings, ElectricalSeverity::Warning),
        new_info: severity_count(&new_findings, ElectricalSeverity::Info),
        resolved_errors: severity_count(&resolved_findings, ElectricalSeverity::Error),
        resolved_warnings: severity_count(&resolved_findings, ElectricalSeverity::Warning),
        resolved_info: severity_count(&resolved_findings, ElectricalSeverity::Info),
        severity_changes: severity_changes.len(),
        escalated_errors: severity_changes
            .iter()
            .filter(|change| {
                change.current_severity == ElectricalSeverity::Error
                    && change.baseline_severity != ElectricalSeverity::Error
            })
            .count(),
        unchanged: current_by_id
            .keys()
            .filter(|id| {
                baseline_by_id.get(*id).is_some_and(|baseline_finding| {
                    baseline_finding.severity == current_by_id[**id].severity
                })
            })
            .count(),
        error_regressions: 0,
    };
    let mut error_regression_ids = new_findings
        .iter()
        .filter(|finding| finding.severity == ElectricalSeverity::Error)
        .map(|finding| finding.id.as_str())
        .collect::<BTreeSet<_>>();
    error_regression_ids.extend(
        severity_changes
            .iter()
            .filter(|change| change.current_severity == ElectricalSeverity::Error)
            .map(|change| change.id.as_str()),
    );
    error_regression_ids.extend(
        current
            .findings
            .iter()
            .filter(|finding| {
                finding.severity == ElectricalSeverity::Error
                    && is_electrical_safety_floor_rule(&finding.rule)
            })
            .map(|finding| finding.id.as_str()),
    );
    let counts = ElectricalComparisonCounts {
        error_regressions: error_regression_ids.len(),
        ..counts
    };

    Ok(ElectricalReviewComparison {
        schema_version: 1,
        baseline: review_identity(baseline)?,
        current: review_identity(current)?,
        passed: counts.error_regressions == 0,
        counts,
        new_findings,
        resolved_findings,
        severity_changes,
    })
}

fn validate_review(review: &ElectricalReview, label: &str) -> Result<(), String> {
    if review.schema_version != 1 {
        return Err(format!(
            "unsupported {label} electrical review schema version {}",
            review.schema_version
        ));
    }
    if review.findings.len() > MAX_FINDINGS {
        return Err(format!(
            "{label} electrical review exceeds the {MAX_FINDINGS} finding limit"
        ));
    }
    if review.policy_id.trim().is_empty() {
        return Err(format!(
            "{label} electrical review policy id must not be blank"
        ));
    }
    for (field, digest) in [
        ("schematic_sha256", review.schematic_sha256.as_str()),
        ("policy_sha256", review.policy_sha256.as_str()),
    ] {
        if !is_sha256(digest) {
            return Err(format!("{label} electrical review has invalid {field}"));
        }
    }

    let mut ids = BTreeSet::new();
    for finding in &review.findings {
        if !is_finding_id(&finding.id) {
            return Err(format!(
                "{label} electrical review has invalid finding id {}",
                finding.id
            ));
        }
        if finding.rule.trim().is_empty() || finding.message.trim().is_empty() {
            return Err(format!(
                "{label} electrical review finding {} has a blank rule or message",
                finding.id
            ));
        }
        if is_electrical_safety_floor_rule(&finding.rule)
            && finding.severity != ElectricalSeverity::Error
        {
            return Err(format!(
                "{label} electrical review finding {} demotes immutable safety-floor rule {}",
                finding.id, finding.rule
            ));
        }
        if !ids.insert(finding.id.as_str()) {
            return Err(format!(
                "{label} electrical review has duplicate finding id {}",
                finding.id
            ));
        }
    }

    let actual = ElectricalFindingCounts {
        errors: review
            .findings
            .iter()
            .filter(|finding| finding.severity == ElectricalSeverity::Error)
            .count(),
        warnings: review
            .findings
            .iter()
            .filter(|finding| finding.severity == ElectricalSeverity::Warning)
            .count(),
        info: review
            .findings
            .iter()
            .filter(|finding| finding.severity == ElectricalSeverity::Info)
            .count(),
    };
    if review.counts != actual {
        return Err(format!(
            "{label} electrical review finding counts are inconsistent"
        ));
    }
    if review.approved != (actual.errors == 0) {
        return Err(format!(
            "{label} electrical review approval is inconsistent with its error count"
        ));
    }
    Ok(())
}

fn review_identity(review: &ElectricalReview) -> Result<ElectricalReviewIdentity, String> {
    let bytes = serde_json::to_vec(review)
        .map_err(|error| format!("serializing electrical review: {error}"))?;
    Ok(ElectricalReviewIdentity {
        review_sha256: hex_digest(&bytes),
        schematic_sha256: review.schematic_sha256.clone(),
        policy_sha256: review.policy_sha256.clone(),
        policy_id: review.policy_id.clone(),
    })
}

fn finding_summary(finding: &ElectricalFinding) -> ElectricalFindingSummary {
    ElectricalFindingSummary {
        id: finding.id.clone(),
        rule: finding.rule.clone(),
        severity: finding.severity,
        message: finding.message.clone(),
    }
}

fn severity_count(findings: &[ElectricalFindingSummary], severity: ElectricalSeverity) -> usize {
    findings
        .iter()
        .filter(|finding| finding.severity == severity)
        .count()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_finding_id(value: &str) -> bool {
    value.strip_prefix("pcbex-er-").is_some_and(|suffix| {
        suffix.len() == 16
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn electrical_review_comparison_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/electrical-review-comparison-v1.json",
        "title": "pcbex electrical review baseline comparison",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "baseline", "current", "passed", "counts",
            "new_findings", "resolved_findings", "severity_changes"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "baseline": {"$ref": "#/$defs/review_identity"},
            "current": {"$ref": "#/$defs/review_identity"},
            "passed": {"type": "boolean"},
            "counts": {"$ref": "#/$defs/counts"},
            "new_findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}},
            "resolved_findings": {"type": "array", "items": {"$ref": "#/$defs/finding"}},
            "severity_changes": {
                "type": "array",
                "items": {"$ref": "#/$defs/severity_change"}
            }
        },
        "$defs": {
            "review_identity": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "review_sha256", "schematic_sha256", "policy_sha256", "policy_id"
                ],
                "properties": {
                    "review_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "policy_id": {"type": "string", "minLength": 1}
                }
            },
            "finding": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "rule", "severity", "message"],
                "properties": {
                    "id": {"type": "string", "pattern": "^pcbex-er-[0-9a-f]{16}$"},
                    "rule": {"type": "string", "minLength": 1},
                    "severity": {"enum": ["info", "warning", "error"]},
                    "message": {"type": "string", "minLength": 1}
                }
            },
            "severity_change": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "rule", "baseline_severity", "current_severity"],
                "properties": {
                    "id": {"type": "string", "pattern": "^pcbex-er-[0-9a-f]{16}$"},
                    "rule": {"type": "string", "minLength": 1},
                    "baseline_severity": {"enum": ["info", "warning", "error"]},
                    "current_severity": {"enum": ["info", "warning", "error"]}
                }
            },
            "counts": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "new_errors", "new_warnings", "new_info", "resolved_errors",
                    "resolved_warnings", "resolved_info", "severity_changes",
                    "escalated_errors", "unchanged", "error_regressions"
                ],
                "properties": {
                    "new_errors": {"type": "integer", "minimum": 0},
                    "new_warnings": {"type": "integer", "minimum": 0},
                    "new_info": {"type": "integer", "minimum": 0},
                    "resolved_errors": {"type": "integer", "minimum": 0},
                    "resolved_warnings": {"type": "integer", "minimum": 0},
                    "resolved_info": {"type": "integer", "minimum": 0},
                    "severity_changes": {"type": "integer", "minimum": 0},
                    "escalated_errors": {"type": "integer", "minimum": 0},
                    "unchanged": {"type": "integer", "minimum": 0},
                    "error_regressions": {"type": "integer", "minimum": 0}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ElectricalPolicy, check_schematic, import_schematic};

    const SOURCE: &str = include_str!("../../../examples/simple.kicad_sch");

    fn review() -> ElectricalReview {
        check_schematic(
            &import_schematic(SOURCE).unwrap(),
            &ElectricalPolicy::default(),
        )
        .unwrap()
    }

    #[test]
    fn comparison_tracks_new_resolved_and_escalated_findings() {
        let mut baseline = review();
        baseline.findings = vec![
            advisory_finding(
                "pcbex-er-1111111111111111",
                "missing_footprint",
                ElectricalSeverity::Warning,
            ),
            advisory_finding(
                "pcbex-er-fedcba9876543210",
                "input_not_driven",
                ElectricalSeverity::Error,
            ),
        ];
        refresh_review(&mut baseline);
        let mut current = baseline.clone();
        current.findings[0].severity = ElectricalSeverity::Error;
        let resolved = current.findings.pop().unwrap();
        current.findings.push(advisory_finding(
            "pcbex-er-0123456789abcdef",
            "multiple_net_names",
            ElectricalSeverity::Error,
        ));
        refresh_review(&mut current);

        let comparison = compare_electrical_reviews(&baseline, &current).unwrap();
        assert!(!comparison.passed);
        assert_eq!(comparison.counts.new_errors, 1);
        assert_eq!(
            comparison.counts.resolved_errors,
            usize::from(resolved.severity == ElectricalSeverity::Error)
        );
        assert_eq!(
            comparison.counts.resolved_warnings,
            usize::from(resolved.severity == ElectricalSeverity::Warning)
        );
        assert_eq!(comparison.counts.escalated_errors, 1);
        assert_eq!(comparison.counts.error_regressions, 2);
        assert_eq!(comparison.severity_changes.len(), 1);
    }

    #[test]
    fn existing_non_floor_errors_do_not_fail_the_baseline_gate() {
        let mut baseline = review();
        baseline.findings = vec![advisory_finding(
            "pcbex-er-1111111111111111",
            "missing_footprint",
            ElectricalSeverity::Error,
        )];
        refresh_review(&mut baseline);
        let comparison = compare_electrical_reviews(&baseline, &baseline).unwrap();
        assert!(comparison.passed);
        assert_eq!(comparison.counts.error_regressions, 0);
        assert_eq!(comparison.counts.unchanged, baseline.findings.len());
    }

    #[test]
    fn retained_safety_floor_errors_fail_the_baseline_gate() {
        let baseline = review();
        let floor_errors = baseline
            .findings
            .iter()
            .filter(|finding| {
                finding.severity == ElectricalSeverity::Error
                    && is_electrical_safety_floor_rule(&finding.rule)
            })
            .count();
        assert!(floor_errors > 0);
        let comparison = compare_electrical_reviews(&baseline, &baseline).unwrap();
        assert!(!comparison.passed);
        assert_eq!(comparison.counts.error_regressions, floor_errors);
        assert_eq!(comparison.counts.new_errors, 0);
        assert_eq!(comparison.counts.escalated_errors, 0);
    }

    #[test]
    fn demoted_safety_floor_findings_fail_closed() {
        let mut baseline = review();
        baseline.findings[0].severity = ElectricalSeverity::Warning;
        refresh_review(&mut baseline);
        let error = compare_electrical_reviews(&baseline, &baseline).unwrap_err();
        assert!(error.contains("demotes immutable safety-floor rule"));
    }

    #[test]
    fn malformed_reviews_fail_closed() {
        let baseline = review();
        let mut duplicate = baseline.clone();
        duplicate.findings.push(duplicate.findings[0].clone());
        refresh_review(&mut duplicate);
        assert!(compare_electrical_reviews(&baseline, &duplicate).is_err());

        let mut inconsistent = baseline.clone();
        inconsistent.counts.errors += 1;
        assert!(compare_electrical_reviews(&baseline, &inconsistent).is_err());

        let mut mismatched_rule = baseline.clone();
        mismatched_rule.findings[0].rule = "different_rule".into();
        assert!(compare_electrical_reviews(&baseline, &mismatched_rule).is_err());
    }

    #[test]
    fn schema_closes_every_declared_object() {
        let schema = electrical_review_comparison_json_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["additionalProperties"], false);
        for definition in schema["$defs"].as_object().unwrap().values() {
            if definition["type"] == "object" {
                assert_eq!(definition["additionalProperties"], false);
            }
        }
    }

    fn refresh_review(review: &mut ElectricalReview) {
        review.counts = ElectricalFindingCounts {
            errors: review
                .findings
                .iter()
                .filter(|finding| finding.severity == ElectricalSeverity::Error)
                .count(),
            warnings: review
                .findings
                .iter()
                .filter(|finding| finding.severity == ElectricalSeverity::Warning)
                .count(),
            info: review
                .findings
                .iter()
                .filter(|finding| finding.severity == ElectricalSeverity::Info)
                .count(),
        };
        review.approved = review.counts.errors == 0;
    }

    fn advisory_finding(id: &str, rule: &str, severity: ElectricalSeverity) -> ElectricalFinding {
        ElectricalFinding {
            id: id.into(),
            rule: rule.into(),
            severity,
            message: format!("synthetic {rule} finding"),
            net_id: None,
            symbols: Vec::new(),
            pins: Vec::new(),
        }
    }
}
