use crate::{
    checking::{CheckReport, Violation},
    quality::RoutingQuality,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnalysisMetrics {
    pub total_length_nm: i64,
    pub total_vias: usize,
    pub total_bends: usize,
    pub routed_nets: usize,
    pub unrouted_nets: usize,
    pub violations: usize,
}

impl AnalysisMetrics {
    fn from_reports(quality: &RoutingQuality, checks: &CheckReport) -> Self {
        Self {
            total_length_nm: quality.total_length_nm,
            total_vias: quality.total_vias,
            total_bends: quality.total_bends,
            routed_nets: quality.routed_nets,
            unrouted_nets: quality.unrouted_nets,
            violations: checks.violations.len(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalysisMetricChanges {
    pub total_length_nm: i64,
    pub total_length_percent: Option<f64>,
    pub total_vias: i64,
    pub total_bends: i64,
    pub routed_nets: i64,
    pub unrouted_nets: i64,
    pub violations: i64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ViolationFingerprint {
    pub rule: String,
    pub message: String,
    pub net_ids: Vec<u32>,
}

impl From<&Violation> for ViolationFingerprint {
    fn from(violation: &Violation) -> Self {
        let mut net_ids = violation.net_ids.clone();
        net_ids.sort_unstable();
        net_ids.dedup();
        Self {
            rule: violation.rule.clone(),
            message: violation.message.clone(),
            net_ids,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnalysisDelta {
    pub schema_version: u32,
    pub baseline: AnalysisMetrics,
    pub current: AnalysisMetrics,
    pub changes: AnalysisMetricChanges,
    pub quality_regressions: Vec<String>,
    pub new_violations: Vec<ViolationFingerprint>,
    pub resolved_violations: Vec<ViolationFingerprint>,
}

impl AnalysisDelta {
    pub fn between(
        baseline_quality: &RoutingQuality,
        baseline_checks: &CheckReport,
        current_quality: &RoutingQuality,
        current_checks: &CheckReport,
    ) -> Self {
        let baseline = AnalysisMetrics::from_reports(baseline_quality, baseline_checks);
        let current = AnalysisMetrics::from_reports(current_quality, current_checks);
        let length_change = signed_delta(current.total_length_nm, baseline.total_length_nm);
        let baseline_violations = fingerprints(baseline_checks);
        let current_violations = fingerprints(current_checks);
        let new_violations = current_violations
            .difference(&baseline_violations)
            .cloned()
            .collect();
        let resolved_violations = baseline_violations
            .difference(&current_violations)
            .cloned()
            .collect();
        let mut quality_regressions = current_quality.regressions_against(baseline_quality);
        if current.routed_nets < baseline.routed_nets {
            quality_regressions.push(format!(
                "routed-net count regressed from {} to {}",
                baseline.routed_nets, current.routed_nets
            ));
        }
        Self {
            schema_version: 1,
            changes: AnalysisMetricChanges {
                total_length_nm: length_change,
                total_length_percent: (baseline.total_length_nm != 0).then_some(
                    length_change as f64 / baseline.total_length_nm.unsigned_abs() as f64 * 100.0,
                ),
                total_vias: count_delta(current.total_vias, baseline.total_vias),
                total_bends: count_delta(current.total_bends, baseline.total_bends),
                routed_nets: count_delta(current.routed_nets, baseline.routed_nets),
                unrouted_nets: count_delta(current.unrouted_nets, baseline.unrouted_nets),
                violations: count_delta(current.violations, baseline.violations),
            },
            baseline,
            current,
            quality_regressions,
            new_violations,
            resolved_violations,
        }
    }

    pub fn is_regression(&self) -> bool {
        !self.quality_regressions.is_empty() || !self.new_violations.is_empty()
    }
}

pub fn analysis_delta_to_sarif(delta: &AnalysisDelta) -> serde_json::Value {
    let mut results = delta
        .quality_regressions
        .iter()
        .map(|message| {
            serde_json::json!({
                "ruleId": "routing_quality_regression",
                "level": "error",
                "message": {"text": message}
            })
        })
        .collect::<Vec<_>>();
    results.extend(delta.new_violations.iter().map(|violation| {
        serde_json::json!({
            "ruleId": violation.rule,
            "level": "error",
            "message": {"text": format!("new violation: {}", violation.message)},
            "properties": {"netIds": violation.net_ids}
        })
    }));
    let mut rule_ids = delta
        .new_violations
        .iter()
        .map(|violation| violation.rule.clone())
        .collect::<BTreeSet<_>>();
    if !delta.quality_regressions.is_empty() {
        rule_ids.insert("routing_quality_regression".to_string());
    }
    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "pcbex compare-analysis",
                    "informationUri": "https://github.com/penguin425/pcbex",
                    "rules": rule_ids.iter().map(|rule| serde_json::json!({
                        "id": rule,
                        "shortDescription": {"text": rule.replace('_', " ")}
                    })).collect::<Vec<_>>()
                }
            },
            "results": results
        }]
    })
}

fn fingerprints(report: &CheckReport) -> BTreeSet<ViolationFingerprint> {
    report
        .violations
        .iter()
        .map(ViolationFingerprint::from)
        .collect()
}

fn signed_delta(current: i64, baseline: i64) -> i64 {
    (i128::from(current) - i128::from(baseline)).clamp(i128::from(i64::MIN), i128::from(i64::MAX))
        as i64
}

fn count_delta(current: usize, baseline: usize) -> i64 {
    (current as i128 - baseline as i128).clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quality(length: i64, vias: usize, bends: usize, routed: usize) -> RoutingQuality {
        RoutingQuality {
            total_length_nm: length,
            total_vias: vias,
            total_bends: bends,
            routed_nets: routed,
            unrouted_nets: 4 - routed,
            nets: vec![],
            differential_pairs: vec![],
        }
    }

    fn report(rule: &str, net_ids: Vec<u32>) -> CheckReport {
        CheckReport {
            violations: vec![Violation {
                rule: rule.to_string(),
                message: format!("{rule} finding"),
                net_ids,
            }],
        }
    }

    #[test]
    fn compares_quality_and_violation_identity_deterministically() {
        let delta = AnalysisDelta::between(
            &quality(1_000, 2, 4, 4),
            &report("clearance", vec![2, 1, 1]),
            &quality(900, 3, 4, 3),
            &report("unrouted", vec![3]),
        );

        assert_eq!(delta.changes.total_length_nm, -100);
        assert_eq!(delta.changes.total_length_percent, Some(-10.0));
        assert_eq!(delta.changes.total_vias, 1);
        assert_eq!(delta.changes.routed_nets, -1);
        assert_eq!(delta.new_violations[0].rule, "unrouted");
        assert_eq!(delta.resolved_violations[0].net_ids, vec![1, 2]);
        assert!(delta.is_regression());
        assert_eq!(delta.quality_regressions.len(), 3);
    }

    #[test]
    fn sarif_contains_quality_and_new_violation_results() {
        let delta = AnalysisDelta::between(
            &quality(1_000, 2, 4, 3),
            &CheckReport::default(),
            &quality(1_100, 2, 4, 3),
            &report("clearance", vec![1]),
        );
        let sarif = analysis_delta_to_sarif(&delta);

        assert_eq!(sarif["version"], "2.1.0");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 2);
    }
}
