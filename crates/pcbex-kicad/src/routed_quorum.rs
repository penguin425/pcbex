use super::{
    AiApprovalQuorumCandidate, AiApprovalQuorumPolicy, AiApprovalQuorumReport, AiModelIdentity,
    AiReviewRequest, SchematicReviewerRoutingPlan, verify_ai_approval_quorum,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Write;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedAiApprovalProfile {
    pub profile_id: String,
    pub title: String,
    pub minimum_reviewers: u32,
    pub reviewer_candidates: Vec<AiModelIdentity>,
    pub approved_signers: Vec<String>,
    pub approved_models: Vec<AiModelIdentity>,
    pub approvals: u32,
    pub profile_met: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedAiApprovalQuorumReport {
    pub schema_version: u32,
    pub routing_policy_id: String,
    pub routing_policy_sha256: String,
    pub baseline_schematic_sha256: String,
    pub current_schematic_sha256: String,
    pub quorum: AiApprovalQuorumReport,
    pub profiles: Vec<RoutedAiApprovalProfile>,
    pub routed_quorum_met: bool,
    pub routed_quorum_failures: Vec<String>,
}

pub fn verify_routed_ai_approval_quorum(
    request: &AiReviewRequest,
    candidates: &[AiApprovalQuorumCandidate<'_>],
    quorum_policy: AiApprovalQuorumPolicy,
    plan: &SchematicReviewerRoutingPlan,
) -> Result<RoutedAiApprovalQuorumReport, String> {
    validate_plan(request, plan)?;
    let quorum = verify_ai_approval_quorum(request, candidates, quorum_policy)?;
    Ok(evaluate(quorum, plan))
}

fn validate_plan(
    request: &AiReviewRequest,
    plan: &SchematicReviewerRoutingPlan,
) -> Result<(), String> {
    if plan.schema_version != 1 {
        return Err(format!(
            "unsupported reviewer routing plan schema version {}",
            plan.schema_version
        ));
    }
    if plan.current_schematic_sha256 != request.electrical_review.schematic_sha256 {
        return Err("routing plan schematic does not match the AI review request".into());
    }
    if !plan.all_changes_routed || (plan.review_required && plan.routes.is_empty()) {
        return Err("routing plan does not assign every required review".into());
    }
    if plan.route_count != plan.routes.len() {
        return Err("routing plan route_count is inconsistent".into());
    }
    let assignments = plan.routes.iter().try_fold(0_u32, |sum, route| {
        sum.checked_add(route.minimum_reviewers)
            .ok_or_else(|| "routing plan assignment count overflowed".to_string())
    })?;
    if assignments != plan.minimum_review_assignments {
        return Err("routing plan minimum_review_assignments is inconsistent".into());
    }
    let mut ids = BTreeSet::new();
    for route in &plan.routes {
        if !ids.insert(route.profile_id.as_str()) {
            return Err(format!(
                "routing plan repeats profile {:?}",
                route.profile_id
            ));
        }
        if route.minimum_reviewers == 0
            || route.minimum_reviewers as usize > route.reviewer_candidates.len()
        {
            return Err(format!(
                "routing profile {} has an impossible threshold",
                route.profile_id
            ));
        }
    }
    Ok(())
}

fn evaluate(
    quorum: AiApprovalQuorumReport,
    plan: &SchematicReviewerRoutingPlan,
) -> RoutedAiApprovalQuorumReport {
    let mut failures = quorum.quorum_failures.clone();
    let profiles = plan
        .routes
        .iter()
        .map(|route| {
            let approved = quorum
                .members
                .iter()
                .filter(|member| member.approved)
                .filter(|member| {
                    route.reviewer_candidates.iter().any(|candidate| {
                        same_identity(
                            &member.provider,
                            &member.model,
                            member.version.as_deref(),
                            candidate,
                        )
                    })
                })
                .collect::<Vec<_>>();
            let approvals = approved.len() as u32;
            let profile_met = approvals >= route.minimum_reviewers;
            if !profile_met {
                failures.push(format!(
                    "insufficient_profile_approvals:{}:required={}:actual={}",
                    route.profile_id, route.minimum_reviewers, approvals
                ));
            }
            RoutedAiApprovalProfile {
                profile_id: route.profile_id.clone(),
                title: route.title.clone(),
                minimum_reviewers: route.minimum_reviewers,
                reviewer_candidates: route.reviewer_candidates.clone(),
                approved_signers: approved
                    .iter()
                    .map(|member| member.signer_id.clone())
                    .collect(),
                approved_models: approved
                    .iter()
                    .map(|member| AiModelIdentity {
                        provider: member.provider.clone(),
                        model: member.model.clone(),
                        version: member.version.clone(),
                    })
                    .collect(),
                approvals,
                profile_met,
            }
        })
        .collect();
    RoutedAiApprovalQuorumReport {
        schema_version: 1,
        routing_policy_id: plan.policy_id.clone(),
        routing_policy_sha256: plan.policy_sha256.clone(),
        baseline_schematic_sha256: plan.baseline_schematic_sha256.clone(),
        current_schematic_sha256: plan.current_schematic_sha256.clone(),
        routed_quorum_met: failures.is_empty(),
        quorum,
        profiles,
        routed_quorum_failures: failures,
    }
}

fn same_identity(
    provider: &str,
    model: &str,
    version: Option<&str>,
    candidate: &AiModelIdentity,
) -> bool {
    canonical(provider) == canonical(&candidate.provider)
        && canonical(model) == canonical(&candidate.model)
        && version.map(canonical) == candidate.version.as_deref().map(canonical)
}

fn canonical(value: &str) -> String {
    value.trim().to_lowercase()
}

pub fn render_routed_ai_approval_quorum_summary(report: &RoutedAiApprovalQuorumReport) -> String {
    let mut output = String::from("# Routed AI schematic approval quorum\n\n");
    let _ = writeln!(
        output,
        "**Result:** {}\n\n| Reviewer profile | Actual | Required | Result |\n| --- | ---: | ---: | --- |",
        if report.routed_quorum_met {
            "approved"
        } else {
            "routed quorum not met"
        }
    );
    for profile in &report.profiles {
        let _ = writeln!(
            output,
            "| {} (`{}`) | {} | {} | {} |",
            profile.title,
            profile.profile_id,
            profile.approvals,
            profile.minimum_reviewers,
            if profile.profile_met { "pass" } else { "fail" }
        );
    }
    for failure in &report.routed_quorum_failures {
        let _ = writeln!(output, "\n- `{failure}`");
    }
    output
}

pub fn routed_ai_approval_quorum_report_json_schema() -> Value {
    let nonblank = json!({"type": "string", "minLength": 1});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/routed-ai-approval-quorum-report-v1.json",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "routing_policy_id", "routing_policy_sha256",
            "baseline_schematic_sha256", "current_schematic_sha256", "quorum", "profiles",
            "routed_quorum_met", "routed_quorum_failures"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "routing_policy_id": nonblank,
            "routing_policy_sha256": {"$ref": "#/$defs/digest"},
            "baseline_schematic_sha256": {"$ref": "#/$defs/digest"},
            "current_schematic_sha256": {"$ref": "#/$defs/digest"},
            "quorum": super::ai_approval_quorum_report_json_schema(),
            "profiles": {"type": "array", "maxItems": 100, "items": {"$ref": "#/$defs/profile"}},
            "routed_quorum_met": {"type": "boolean"},
            "routed_quorum_failures": {"type": "array", "items": nonblank}
        },
        "$defs": {
            "digest": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "model": {
                "type": "object", "additionalProperties": false,
                "required": ["provider", "model", "version"],
                "properties": {
                    "provider": nonblank, "model": nonblank,
                    "version": {"type": ["string", "null"], "minLength": 1}
                }
            },
            "profile": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "profile_id", "title", "minimum_reviewers", "reviewer_candidates",
                    "approved_signers", "approved_models", "approvals", "profile_met"
                ],
                "properties": {
                    "profile_id": nonblank, "title": nonblank,
                    "minimum_reviewers": {"type": "integer", "minimum": 1, "maximum": 100},
                    "reviewer_candidates": {"type": "array", "items": {"$ref": "#/$defs/model"}},
                    "approved_signers": {"type": "array", "items": nonblank},
                    "approved_models": {"type": "array", "items": {"$ref": "#/$defs/model"}},
                    "approvals": {"type": "integer", "minimum": 0, "maximum": 100},
                    "profile_met": {"type": "boolean"}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AiApprovalQuorumCounts, AiApprovalQuorumMember, SchematicReviewerRoute,
        SchematicReviewerRoutingPlan,
    };

    fn plan() -> SchematicReviewerRoutingPlan {
        SchematicReviewerRoutingPlan {
            schema_version: 1,
            policy_id: "routing-v1".into(),
            policy_sha256: "a".repeat(64),
            baseline_schematic_sha256: "b".repeat(64),
            current_schematic_sha256: "c".repeat(64),
            changed: true,
            review_required: true,
            all_changes_routed: true,
            change_count: 1,
            route_count: 1,
            minimum_review_assignments: 1,
            routes: vec![SchematicReviewerRoute {
                profile_id: "power".into(),
                title: "Power".into(),
                minimum_reviewers: 1,
                reviewer_candidates: vec![AiModelIdentity {
                    provider: "Provider-A".into(),
                    model: "Power".into(),
                    version: Some("1".into()),
                }],
                instructions: vec!["Review power".into()],
                matched_changes: Vec::new(),
                fallback_changes: Vec::new(),
            }],
        }
    }

    fn quorum(model: &str) -> AiApprovalQuorumReport {
        AiApprovalQuorumReport {
            schema_version: 1,
            request_sha256: "d".repeat(64),
            policy: AiApprovalQuorumPolicy {
                minimum_approvals: 1,
                minimum_distinct_providers: 1,
                minimum_distinct_models: 1,
            },
            counts: AiApprovalQuorumCounts {
                members: 1,
                approvals: 1,
                rejections: 0,
                distinct_providers: 1,
                distinct_models: 1,
            },
            members: vec![AiApprovalQuorumMember {
                signer_id: "reviewer".into(),
                public_key: "e".repeat(64),
                response_sha256: "f".repeat(64),
                provider: "provider-a".into(),
                model: model.into(),
                version: Some("1".into()),
                approved: true,
                gate_failures: Vec::new(),
            }],
            quorum_met: true,
            quorum_failures: Vec::new(),
        }
    }

    #[test]
    fn enforces_profile_candidates() {
        assert!(evaluate(quorum("power"), &plan()).routed_quorum_met);
        assert!(!evaluate(quorum("general"), &plan()).routed_quorum_met);
    }

    #[test]
    fn schema_is_closed() {
        let schema = routed_ai_approval_quorum_report_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["$defs"]["profile"]["additionalProperties"], false);
    }
}
