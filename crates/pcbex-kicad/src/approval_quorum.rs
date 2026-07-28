use super::{
    AiReviewRequest, AiReviewResponse, SignedAiApproval, ai_review_request_sha256,
    verify_signed_ai_approval,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Write;

const MAX_QUORUM_MEMBERS: usize = 100;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiApprovalQuorumPolicy {
    pub minimum_approvals: u32,
    pub minimum_distinct_providers: u32,
    pub minimum_distinct_models: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiApprovalQuorumCounts {
    pub members: u32,
    pub approvals: u32,
    pub rejections: u32,
    pub distinct_providers: u32,
    pub distinct_models: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiApprovalQuorumMember {
    pub signer_id: String,
    pub public_key: String,
    pub response_sha256: String,
    pub provider: String,
    pub model: String,
    pub version: Option<String>,
    pub approved: bool,
    pub gate_failures: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiApprovalQuorumReport {
    pub schema_version: u32,
    pub request_sha256: String,
    pub policy: AiApprovalQuorumPolicy,
    pub counts: AiApprovalQuorumCounts,
    pub members: Vec<AiApprovalQuorumMember>,
    pub quorum_met: bool,
    pub quorum_failures: Vec<String>,
}

pub struct AiApprovalQuorumCandidate<'a> {
    pub approval: &'a SignedAiApproval,
    pub response: &'a AiReviewResponse,
    pub trusted_public_key: &'a [u8; 32],
}

pub fn verify_ai_approval_quorum(
    request: &AiReviewRequest,
    candidates: &[AiApprovalQuorumCandidate<'_>],
    policy: AiApprovalQuorumPolicy,
) -> Result<AiApprovalQuorumReport, String> {
    validate_policy(&policy)?;
    if candidates.is_empty() || candidates.len() > MAX_QUORUM_MEMBERS {
        return Err(format!(
            "AI approval quorum must contain 1 to {MAX_QUORUM_MEMBERS} members"
        ));
    }

    let request_sha256 = ai_review_request_sha256(request)?;
    let mut signer_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut response_digests = BTreeSet::new();
    let mut members = Vec::with_capacity(candidates.len());

    for candidate in candidates {
        verify_signed_ai_approval(
            candidate.approval,
            request,
            candidate.response,
            candidate.trusted_public_key,
        )?;
        if !signer_ids.insert(candidate.approval.signer_id.clone()) {
            return Err(format!(
                "duplicate AI approval quorum signer {:?}",
                candidate.approval.signer_id
            ));
        }
        if !public_keys.insert(candidate.approval.public_key.clone()) {
            return Err("duplicate AI approval quorum public key".into());
        }
        if !response_digests.insert(candidate.approval.response_sha256.clone()) {
            return Err("duplicate AI approval quorum response digest".into());
        }
        members.push(AiApprovalQuorumMember {
            signer_id: candidate.approval.signer_id.clone(),
            public_key: candidate.approval.public_key.clone(),
            response_sha256: candidate.approval.response_sha256.clone(),
            provider: candidate.response.model.provider.trim().to_string(),
            model: candidate.response.model.model.trim().to_string(),
            version: candidate
                .response
                .model
                .version
                .as_deref()
                .map(str::trim)
                .map(str::to_string),
            approved: candidate.approval.approved,
            gate_failures: candidate.approval.gate_failures.clone(),
        });
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));

    let approved = members
        .iter()
        .filter(|member| member.approved)
        .collect::<Vec<_>>();
    let providers = approved
        .iter()
        .map(|member| canonical_identity(&member.provider))
        .collect::<BTreeSet<_>>();
    let models = approved
        .iter()
        .map(|member| {
            format!(
                "{}/{}@{}",
                canonical_identity(&member.provider),
                canonical_identity(&member.model),
                member
                    .version
                    .as_deref()
                    .map(canonical_identity)
                    .unwrap_or_else(|| "-".into())
            )
        })
        .collect::<BTreeSet<_>>();

    let counts = AiApprovalQuorumCounts {
        members: members.len() as u32,
        approvals: approved.len() as u32,
        rejections: (members.len() - approved.len()) as u32,
        distinct_providers: providers.len() as u32,
        distinct_models: models.len() as u32,
    };
    let mut quorum_failures = Vec::new();
    append_threshold_failure(
        &mut quorum_failures,
        "insufficient_approvals",
        policy.minimum_approvals,
        counts.approvals,
    );
    append_threshold_failure(
        &mut quorum_failures,
        "insufficient_distinct_providers",
        policy.minimum_distinct_providers,
        counts.distinct_providers,
    );
    append_threshold_failure(
        &mut quorum_failures,
        "insufficient_distinct_models",
        policy.minimum_distinct_models,
        counts.distinct_models,
    );

    Ok(AiApprovalQuorumReport {
        schema_version: 1,
        request_sha256,
        policy,
        counts,
        members,
        quorum_met: quorum_failures.is_empty(),
        quorum_failures,
    })
}

fn validate_policy(policy: &AiApprovalQuorumPolicy) -> Result<(), String> {
    for (label, value) in [
        ("minimum approvals", policy.minimum_approvals),
        (
            "minimum distinct providers",
            policy.minimum_distinct_providers,
        ),
        ("minimum distinct models", policy.minimum_distinct_models),
    ] {
        if value == 0 || value as usize > MAX_QUORUM_MEMBERS {
            return Err(format!(
                "AI approval quorum {label} must be between 1 and {MAX_QUORUM_MEMBERS}"
            ));
        }
    }
    if policy.minimum_distinct_providers > policy.minimum_approvals {
        return Err("minimum distinct providers cannot exceed minimum approvals".into());
    }
    if policy.minimum_distinct_models > policy.minimum_approvals {
        return Err("minimum distinct models cannot exceed minimum approvals".into());
    }
    Ok(())
}

fn canonical_identity(value: &str) -> String {
    value.trim().to_lowercase()
}

fn append_threshold_failure(failures: &mut Vec<String>, id: &str, required: u32, actual: u32) {
    if actual < required {
        failures.push(format!("{id}:required={required}:actual={actual}"));
    }
}

pub fn render_ai_approval_quorum_summary(report: &AiApprovalQuorumReport) -> String {
    let mut output = String::new();
    let _ = writeln!(output, "# AI schematic approval quorum\n");
    let _ = writeln!(
        output,
        "**Result:** {}\n",
        if report.quorum_met {
            "approved"
        } else {
            "quorum not met"
        }
    );
    let _ = writeln!(
        output,
        "| Metric | Actual | Required |\n| --- | ---: | ---: |"
    );
    let _ = writeln!(
        output,
        "| Signed approvals | {} | {} |",
        report.counts.approvals, report.policy.minimum_approvals
    );
    let _ = writeln!(
        output,
        "| Distinct providers | {} | {} |",
        report.counts.distinct_providers, report.policy.minimum_distinct_providers
    );
    let _ = writeln!(
        output,
        "| Distinct models | {} | {} |",
        report.counts.distinct_models, report.policy.minimum_distinct_models
    );
    let _ = writeln!(
        output,
        "\n| Signer | Provider | Model | Decision |\n| --- | --- | --- | --- |"
    );
    for member in &report.members {
        let version = member.version.as_deref().unwrap_or("-");
        let _ = writeln!(
            output,
            "| `{}` | {} | {}@{} | {} |",
            member.signer_id,
            member.provider,
            member.model,
            version,
            if member.approved { "approve" } else { "reject" }
        );
    }
    if !report.quorum_failures.is_empty() {
        let _ = writeln!(output, "\n## Gate failures\n");
        for failure in &report.quorum_failures {
            let _ = writeln!(output, "- `{failure}`");
        }
    }
    output
}

pub fn ai_approval_quorum_report_json_schema() -> Value {
    let nonblank = json!({"type": "string", "minLength": 1});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/ai-approval-quorum-report-v1.json",
        "title": "pcbex AI schematic approval quorum report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "policy", "counts", "members",
            "quorum_met", "quorum_failures"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy": {"$ref": "#/$defs/policy"},
            "counts": {"$ref": "#/$defs/counts"},
            "members": {
                "type": "array", "minItems": 1, "maxItems": MAX_QUORUM_MEMBERS,
                "items": {"$ref": "#/$defs/member"}
            },
            "quorum_met": {"type": "boolean"},
            "quorum_failures": {"type": "array", "items": nonblank}
        },
        "$defs": {
            "policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "minimum_approvals", "minimum_distinct_providers",
                    "minimum_distinct_models"
                ],
                "properties": {
                    "minimum_approvals": {
                        "type": "integer", "minimum": 1, "maximum": MAX_QUORUM_MEMBERS
                    },
                    "minimum_distinct_providers": {
                        "type": "integer", "minimum": 1, "maximum": MAX_QUORUM_MEMBERS
                    },
                    "minimum_distinct_models": {
                        "type": "integer", "minimum": 1, "maximum": MAX_QUORUM_MEMBERS
                    }
                }
            },
            "counts": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "members", "approvals", "rejections", "distinct_providers",
                    "distinct_models"
                ],
                "properties": {
                    "members": {"type": "integer", "minimum": 1},
                    "approvals": {"type": "integer", "minimum": 0},
                    "rejections": {"type": "integer", "minimum": 0},
                    "distinct_providers": {"type": "integer", "minimum": 0},
                    "distinct_models": {"type": "integer", "minimum": 0}
                }
            },
            "member": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "signer_id", "public_key", "response_sha256", "provider",
                    "model", "version", "approved", "gate_failures"
                ],
                "properties": {
                    "signer_id": nonblank,
                    "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "provider": nonblank,
                    "model": nonblank,
                    "version": {
                        "anyOf": [{"type": "string", "minLength": 1}, {"type": "null"}]
                    },
                    "approved": {"type": "boolean"},
                    "gate_failures": {"type": "array", "items": nonblank}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AiModelIdentity, AiRequirement, AiRequirementAssessment, AiRequirementStatus,
        AiReviewDecision, ElectricalPolicy, ElectricalRulePolicy, ElectricalSeverity,
        build_ai_review_request, check_schematic, import_schematic, sign_ai_review,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    fn request_and_response(provider: &str, model: &str) -> (AiReviewRequest, AiReviewResponse) {
        let schematic =
            import_schematic(include_str!("../../../examples/simple.kicad_sch")).unwrap();
        let mut policy = ElectricalPolicy::default();
        policy.rules = policy
            .rules
            .into_iter()
            .map(|(id, mut setting)| {
                if setting.severity == ElectricalSeverity::Error {
                    setting.enabled = false;
                }
                (id, setting)
            })
            .collect::<BTreeMap<String, ElectricalRulePolicy>>();
        let review = check_schematic(&schematic, &policy).unwrap();
        let request = build_ai_review_request(
            schematic,
            &policy,
            review,
            "a".repeat(64),
            Vec::new(),
            vec![AiRequirement {
                id: "power".into(),
                text: "Power inputs are intentional".into(),
            }],
            false,
        )
        .unwrap();
        let response = AiReviewResponse {
            schema_version: 1,
            request_sha256: ai_review_request_sha256(&request).unwrap(),
            model: AiModelIdentity {
                provider: provider.into(),
                model: model.into(),
                version: Some("1".into()),
            },
            decision: AiReviewDecision::Approve,
            summary: "All supplied requirements and evidence pass.".into(),
            requirements: vec![AiRequirementAssessment {
                id: "power".into(),
                status: AiRequirementStatus::Pass,
                rationale: "Bound to the deterministic review.".into(),
                evidence_refs: vec!["electrical-review".into()],
            }],
            risks: Vec::new(),
        };
        (request, response)
    }

    #[test]
    fn verifies_independent_signed_approvals_and_enforces_thresholds() {
        let (request, response_a) = request_and_response("provider-a", "model-a");
        let mut response_b = response_a.clone();
        response_b.model.provider = "provider-b".into();
        response_b.model.model = "model-b".into();
        let approval_a = sign_ai_review(&request, &response_a, "reviewer-a", &[1; 32]).unwrap();
        let approval_b = sign_ai_review(&request, &response_b, "reviewer-b", &[2; 32]).unwrap();
        let key_a = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let key_b = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
        let candidates = [
            AiApprovalQuorumCandidate {
                approval: &approval_a,
                response: &response_a,
                trusted_public_key: &key_a,
            },
            AiApprovalQuorumCandidate {
                approval: &approval_b,
                response: &response_b,
                trusted_public_key: &key_b,
            },
        ];
        let report = verify_ai_approval_quorum(
            &request,
            &candidates,
            AiApprovalQuorumPolicy {
                minimum_approvals: 2,
                minimum_distinct_providers: 2,
                minimum_distinct_models: 2,
            },
        )
        .unwrap();
        assert!(report.quorum_met);
        assert_eq!(report.counts.approvals, 2);

        let report = verify_ai_approval_quorum(
            &request,
            &candidates,
            AiApprovalQuorumPolicy {
                minimum_approvals: 3,
                minimum_distinct_providers: 2,
                minimum_distinct_models: 2,
            },
        )
        .unwrap();
        assert!(!report.quorum_met);
        assert_eq!(
            report.quorum_failures,
            ["insufficient_approvals:required=3:actual=2"]
        );
    }

    #[test]
    fn rejects_duplicate_votes_and_tampering() {
        let (request, response) = request_and_response("provider", "model");
        let approval = sign_ai_review(&request, &response, "reviewer", &[3; 32]).unwrap();
        let key = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        let duplicate = [
            AiApprovalQuorumCandidate {
                approval: &approval,
                response: &response,
                trusted_public_key: &key,
            },
            AiApprovalQuorumCandidate {
                approval: &approval,
                response: &response,
                trusted_public_key: &key,
            },
        ];
        assert!(
            verify_ai_approval_quorum(
                &request,
                &duplicate,
                AiApprovalQuorumPolicy {
                    minimum_approvals: 2,
                    minimum_distinct_providers: 1,
                    minimum_distinct_models: 1,
                },
            )
            .is_err()
        );

        let mut tampered = approval.clone();
        tampered.signature.replace_range(0..2, "00");
        assert!(
            verify_ai_approval_quorum(
                &request,
                &[AiApprovalQuorumCandidate {
                    approval: &tampered,
                    response: &response,
                    trusted_public_key: &key,
                }],
                AiApprovalQuorumPolicy {
                    minimum_approvals: 1,
                    minimum_distinct_providers: 1,
                    minimum_distinct_models: 1,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn report_schema_is_closed() {
        let schema = ai_approval_quorum_report_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        for definition in schema["$defs"].as_object().unwrap().values() {
            assert_eq!(definition["additionalProperties"], false);
        }
    }
}
