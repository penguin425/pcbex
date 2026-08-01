use super::{
    AiReviewRequest, AiReviewSession, SessionAiApprovalQuorumReport,
    SessionRoutedAiApprovalQuorumReport, ai_review_request_sha256, validate_ai_review_session,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt::Write;

const SIGNATURE_DOMAIN: &str = "pcbex-human-schematic-escalation-v1";
const MAX_HUMAN_REVIEWERS: usize = 100;
const MAX_REASON_BYTES: usize = 4_096;
const MAX_TICKET_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SessionAiQuorumEvidence {
    Routed(Box<SessionRoutedAiApprovalQuorumReport>),
    Global(Box<SessionAiApprovalQuorumReport>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanEscalationDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedHumanEscalation {
    pub schema_version: u32,
    pub session_sha256: String,
    pub request_sha256: String,
    pub ai_quorum_sha256: String,
    pub decision: HumanEscalationDecision,
    pub reason: String,
    pub ticket: String,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEscalationPolicy {
    pub minimum_approvals: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEscalationMember {
    pub signer_id: String,
    pub public_key: String,
    pub decision: HumanEscalationDecision,
    pub reason: String,
    pub ticket: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEscalationReport {
    pub schema_version: u32,
    pub session_sha256: String,
    pub request_sha256: String,
    pub ai_quorum_sha256: String,
    pub evaluated_at_unix: u64,
    pub policy: HumanEscalationPolicy,
    pub approvals: u32,
    pub rejections: u32,
    pub members: Vec<HumanEscalationMember>,
    pub escalation_eligible: bool,
    pub escalation_approved: bool,
    pub gate_failures: Vec<String>,
}

pub struct HumanEscalationCandidate<'a> {
    pub escalation: &'a SignedHumanEscalation,
    pub trusted_public_key: &'a [u8; 32],
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    session_sha256: &'a str,
    request_sha256: &'a str,
    ai_quorum_sha256: &'a str,
    decision: HumanEscalationDecision,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

pub fn ai_quorum_evidence_sha256(evidence: &SessionAiQuorumEvidence) -> Result<String, String> {
    validate_evidence_shape(evidence)?;
    let bytes = serde_json::to_vec(evidence)
        .map_err(|error| format!("serializing AI quorum evidence: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

#[allow(clippy::too_many_arguments)]
pub fn sign_human_escalation(
    request: &AiReviewRequest,
    session: &AiReviewSession,
    evidence: &SessionAiQuorumEvidence,
    decision: HumanEscalationDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedHumanEscalation, String> {
    validate_text(reason, MAX_REASON_BYTES, "human escalation reason")?;
    validate_text(ticket, MAX_TICKET_BYTES, "human escalation ticket")?;
    validate_text(signer_id, 128, "human escalation signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let session_sha256 = super::ai_review_session_sha256(session, request)?;
    validate_evidence_binding(evidence, session, &session_sha256, &request_sha256)?;
    let failures = evidence_eligibility_failures(evidence);
    if !failures.is_empty() {
        return Err(format!(
            "AI quorum evidence is not eligible for human escalation: {}",
            failures.join(", ")
        ));
    }
    let ai_quorum_sha256 = ai_quorum_evidence_sha256(evidence)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = signature_payload(
        &session_sha256,
        &request_sha256,
        &ai_quorum_sha256,
        decision,
        reason,
        ticket,
        signer_id,
    )?;
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedHumanEscalation {
        schema_version: 1,
        session_sha256,
        request_sha256,
        ai_quorum_sha256,
        decision,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn verify_human_escalation(
    request: &AiReviewRequest,
    session: &AiReviewSession,
    evidence: &SessionAiQuorumEvidence,
    evaluated_at_unix: u64,
    candidates: &[HumanEscalationCandidate<'_>],
    policy: HumanEscalationPolicy,
) -> Result<HumanEscalationReport, String> {
    if policy.minimum_approvals < 2 || policy.minimum_approvals as usize > MAX_HUMAN_REVIEWERS {
        return Err(format!(
            "human escalation minimum approvals must be between 2 and {MAX_HUMAN_REVIEWERS}"
        ));
    }
    if candidates.is_empty() || candidates.len() > MAX_HUMAN_REVIEWERS {
        return Err(format!(
            "human escalation must contain 1 to {MAX_HUMAN_REVIEWERS} members"
        ));
    }
    let request_sha256 = ai_review_request_sha256(request)?;
    let session_sha256 = validate_ai_review_session(session, request, evaluated_at_unix)?;
    validate_evidence_binding(evidence, session, &session_sha256, &request_sha256)?;
    let ai_quorum_sha256 = ai_quorum_evidence_sha256(evidence)?;

    let mut signer_ids = BTreeSet::new();
    let mut public_keys = BTreeSet::new();
    let mut members = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        verify_signature(
            candidate.escalation,
            &session_sha256,
            &request_sha256,
            &ai_quorum_sha256,
            candidate.trusted_public_key,
        )?;
        if !signer_ids.insert(candidate.escalation.signer_id.clone()) {
            return Err(format!(
                "duplicate human escalation signer {:?}",
                candidate.escalation.signer_id
            ));
        }
        if !public_keys.insert(candidate.escalation.public_key.clone()) {
            return Err("duplicate human escalation public key".into());
        }
        members.push(HumanEscalationMember {
            signer_id: candidate.escalation.signer_id.clone(),
            public_key: candidate.escalation.public_key.clone(),
            decision: candidate.escalation.decision,
            reason: candidate.escalation.reason.clone(),
            ticket: candidate.escalation.ticket.clone(),
        });
    }
    members.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let approvals = members
        .iter()
        .filter(|member| member.decision == HumanEscalationDecision::Approve)
        .count() as u32;
    let rejections = members.len() as u32 - approvals;
    let mut gate_failures = evidence_eligibility_failures(evidence);
    let escalation_eligible = gate_failures.is_empty();
    if approvals < policy.minimum_approvals {
        gate_failures.push(format!(
            "insufficient_human_approvals:required={}:actual={approvals}",
            policy.minimum_approvals
        ));
    }
    if rejections > 0 {
        gate_failures.push(format!("human_rejection:count={rejections}"));
    }
    let escalation_approved = escalation_eligible && gate_failures.is_empty();
    Ok(HumanEscalationReport {
        schema_version: 1,
        session_sha256,
        request_sha256,
        ai_quorum_sha256,
        evaluated_at_unix,
        policy,
        approvals,
        rejections,
        members,
        escalation_eligible,
        escalation_approved,
        gate_failures,
    })
}

fn verify_signature(
    escalation: &SignedHumanEscalation,
    session_sha256: &str,
    request_sha256: &str,
    ai_quorum_sha256: &str,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    if escalation.schema_version != 1 {
        return Err(format!(
            "unsupported signed human escalation schema version {}",
            escalation.schema_version
        ));
    }
    if escalation.algorithm != "ed25519" {
        return Err(format!(
            "unsupported human escalation signature algorithm {}",
            escalation.algorithm
        ));
    }
    validate_text(
        &escalation.reason,
        MAX_REASON_BYTES,
        "human escalation reason",
    )?;
    validate_text(
        &escalation.ticket,
        MAX_TICKET_BYTES,
        "human escalation ticket",
    )?;
    validate_text(&escalation.signer_id, 128, "human escalation signer id")?;
    if escalation.session_sha256 != session_sha256
        || escalation.request_sha256 != request_sha256
        || escalation.ai_quorum_sha256 != ai_quorum_sha256
    {
        return Err("signed human escalation is bound to different evidence".into());
    }
    let public_key = hex_decode_array::<32>(&escalation.public_key, "human escalation public key")?;
    if &public_key != trusted_public_key {
        return Err("human escalation key does not match the trusted public key".into());
    }
    let signature = hex_decode_array::<64>(&escalation.signature, "human escalation signature")?;
    let payload = signature_payload(
        session_sha256,
        request_sha256,
        ai_quorum_sha256,
        escalation.decision,
        &escalation.reason,
        &escalation.ticket,
        &escalation.signer_id,
    )?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid human escalation public key: {error}"))?
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|error| format!("invalid human escalation signature: {error}"))
}

fn validate_evidence_binding(
    evidence: &SessionAiQuorumEvidence,
    review_session: &AiReviewSession,
    session_sha256: &str,
    request_sha256: &str,
) -> Result<(), String> {
    let report_session = evidence_session(evidence);
    if report_session.schema_version != 1
        || report_session.session_sha256 != session_sha256
        || report_session.request_sha256 != request_sha256
        || report_session.quorum.request_sha256 != request_sha256
        || report_session.issued_at_unix != review_session.issued_at_unix
        || report_session.expires_at_unix != review_session.expires_at_unix
        || report_session.evaluated_at_unix < review_session.issued_at_unix
        || report_session.evaluated_at_unix > review_session.expires_at_unix
    {
        return Err("AI quorum evidence is bound to a different request or session".into());
    }
    validate_evidence_shape(evidence)
}

fn validate_evidence_shape(evidence: &SessionAiQuorumEvidence) -> Result<(), String> {
    let session = evidence_session(evidence);
    if session.quorum.schema_version != 1 {
        return Err("unsupported AI quorum evidence schema version".into());
    }
    let counts = &session.quorum.counts;
    if counts.members != session.quorum.members.len() as u32
        || counts.approvals + counts.rejections != counts.members
        || counts.approvals
            != session
                .quorum
                .members
                .iter()
                .filter(|member| member.approved)
                .count() as u32
    {
        return Err("AI quorum evidence contains inconsistent member counts".into());
    }
    if let SessionAiQuorumEvidence::Routed(report) = evidence
        && (report.schema_version != 1
            || report.routed_quorum.schema_version != 1
            || report.routed_quorum.quorum != report.session.quorum)
    {
        return Err("routed AI quorum evidence is internally inconsistent".into());
    }
    Ok(())
}

fn evidence_eligibility_failures(evidence: &SessionAiQuorumEvidence) -> Vec<String> {
    let session = evidence_session(evidence);
    let final_quorum_met = match evidence {
        SessionAiQuorumEvidence::Global(_) => session.quorum.quorum_met,
        SessionAiQuorumEvidence::Routed(report) => report.routed_quorum.routed_quorum_met,
    };
    let mut failures = Vec::new();
    if final_quorum_met {
        failures.push("ai_quorum_already_approved".into());
    }
    let mut needs_human = false;
    for member in session
        .quorum
        .members
        .iter()
        .filter(|member| !member.approved)
    {
        for failure in &member.gate_failures {
            if failure == "ai_decision_needs_human" {
                needs_human = true;
            } else {
                failures.push(format!(
                    "non_overridable_ai_failure:{}:{failure}",
                    member.signer_id
                ));
            }
        }
        if member.gate_failures.is_empty() {
            failures.push(format!(
                "non_overridable_ai_failure:{}:unspecified_rejection",
                member.signer_id
            ));
        }
    }
    if !needs_human {
        failures.push("no_ai_needs_human_decision".into());
    }
    failures.sort();
    failures.dedup();
    failures
}

fn evidence_session(evidence: &SessionAiQuorumEvidence) -> &SessionAiApprovalQuorumReport {
    match evidence {
        SessionAiQuorumEvidence::Global(report) => report,
        SessionAiQuorumEvidence::Routed(report) => &report.session,
    }
}

fn signature_payload(
    session_sha256: &str,
    request_sha256: &str,
    ai_quorum_sha256: &str,
    decision: HumanEscalationDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        session_sha256,
        request_sha256,
        ai_quorum_sha256,
        decision,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("serializing human escalation signature payload: {error}"))
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum {
        Err(format!("{label} must contain 1 to {maximum} bytes"))
    } else {
        Ok(())
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hex_decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2 {
        return Err(format!("{label} must contain {} hexadecimal digits", N * 2));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or_else(|| format!("invalid {label} hexadecimal"))?;
        let low = hex_nibble(pair[1]).ok_or_else(|| format!("invalid {label} hexadecimal"))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

pub fn render_human_escalation_summary(report: &HumanEscalationReport) -> String {
    let mut output = String::from("# Human schematic escalation\n\n");
    let _ = writeln!(
        output,
        "**Result:** {}\n",
        if report.escalation_approved {
            "approved by dual control"
        } else {
            "not approved"
        }
    );
    let _ = writeln!(output, "- AI quorum: `{}`", report.ai_quorum_sha256);
    let _ = writeln!(
        output,
        "- Human approvals: `{}/{}`",
        report.approvals, report.policy.minimum_approvals
    );
    let _ = writeln!(output, "- Human rejections: `{}`\n", report.rejections);
    for member in &report.members {
        let _ = writeln!(
            output,
            "- `{}`: `{:?}` — {} (`{}`)",
            member.signer_id, member.decision, member.reason, member.ticket
        );
    }
    if !report.gate_failures.is_empty() {
        let _ = writeln!(output, "\n## Gate failures\n");
        for failure in &report.gate_failures {
            let _ = writeln!(output, "- `{failure}`");
        }
    }
    output
}

pub fn signed_human_escalation_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-human-escalation-v1.json",
        "title": "pcbex signed human schematic escalation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "session_sha256", "request_sha256", "ai_quorum_sha256",
            "decision", "reason", "ticket", "signer_id", "algorithm", "public_key",
            "signature"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "session_sha256": digest,
            "request_sha256": digest,
            "ai_quorum_sha256": digest,
            "decision": {"enum": ["approve", "reject"]},
            "reason": {"type": "string", "minLength": 1, "maxLength": MAX_REASON_BYTES},
            "ticket": {"type": "string", "minLength": 1, "maxLength": MAX_TICKET_BYTES},
            "signer_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "algorithm": {"const": "ed25519"},
            "public_key": digest,
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub fn human_escalation_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let nonblank = json!({"type": "string", "minLength": 1});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/human-escalation-report-v1.json",
        "title": "pcbex human schematic escalation report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "session_sha256", "request_sha256", "ai_quorum_sha256",
            "evaluated_at_unix", "policy", "approvals", "rejections", "members",
            "escalation_eligible", "escalation_approved", "gate_failures"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "session_sha256": digest,
            "request_sha256": digest,
            "ai_quorum_sha256": digest,
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "policy": {
                "type": "object", "additionalProperties": false,
                "required": ["minimum_approvals"],
                "properties": {
                    "minimum_approvals": {
                        "type": "integer", "minimum": 2, "maximum": MAX_HUMAN_REVIEWERS
                    }
                }
            },
            "approvals": {"type": "integer", "minimum": 0},
            "rejections": {"type": "integer", "minimum": 0},
            "members": {
                "type": "array", "minItems": 1, "maxItems": MAX_HUMAN_REVIEWERS,
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["signer_id", "public_key", "decision", "reason", "ticket"],
                    "properties": {
                        "signer_id": nonblank,
                        "public_key": digest,
                        "decision": {"enum": ["approve", "reject"]},
                        "reason": nonblank,
                        "ticket": nonblank
                    }
                }
            },
            "escalation_eligible": {"type": "boolean"},
            "escalation_approved": {"type": "boolean"},
            "gate_failures": {"type": "array", "items": nonblank}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AiApprovalQuorumCandidate, AiApprovalQuorumPolicy, AiModelIdentity, AiRequirement,
        AiRequirementAssessment, AiRequirementStatus, AiReviewDecision, AiReviewResponse,
        ElectricalPolicy, ElectricalRulePolicy, ElectricalSeverity, build_ai_review_request,
        build_ai_review_session, check_schematic, import_schematic, sign_ai_review_for_session,
        verify_session_ai_approval_quorum,
    };
    use std::collections::BTreeMap;

    fn needs_human_evidence() -> (AiReviewRequest, AiReviewSession, SessionAiQuorumEvidence) {
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
                id: "intent".into(),
                text: "The circuit intent is satisfied".into(),
            }],
            false,
        )
        .unwrap();
        let session = build_ai_review_session(&request, &"b".repeat(64), 1_000, 2_000).unwrap();
        let response = AiReviewResponse {
            schema_version: 1,
            request_sha256: ai_review_request_sha256(&request).unwrap(),
            model: AiModelIdentity {
                provider: "provider".into(),
                model: "model".into(),
                version: Some("1".into()),
            },
            decision: AiReviewDecision::NeedsHuman,
            summary: "Human judgment is required.".into(),
            requirements: vec![AiRequirementAssessment {
                id: "intent".into(),
                status: AiRequirementStatus::Pass,
                rationale: "Electrical evidence passes.".into(),
                evidence_refs: vec!["electrical-review".into()],
            }],
            risks: Vec::new(),
        };
        let approval = sign_ai_review_for_session(
            &request,
            &response,
            &session.session_sha256,
            "ai-reviewer",
            &[1; 32],
        )
        .unwrap();
        let ai_key = SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes();
        let report = verify_session_ai_approval_quorum(
            &request,
            &session,
            1_100,
            &[AiApprovalQuorumCandidate {
                approval: &approval,
                response: &response,
                trusted_public_key: &ai_key,
            }],
            AiApprovalQuorumPolicy {
                minimum_approvals: 1,
                minimum_distinct_providers: 1,
                minimum_distinct_models: 1,
            },
        )
        .unwrap();
        (
            request,
            session,
            SessionAiQuorumEvidence::Global(Box::new(report)),
        )
    }

    #[test]
    fn requires_two_distinct_human_approvals_for_needs_human_evidence() {
        let (request, session, evidence) = needs_human_evidence();
        let first = sign_human_escalation(
            &request,
            &session,
            &evidence,
            HumanEscalationDecision::Approve,
            "Reviewed the design intent and supporting evidence.",
            "HW-42",
            "engineer-a",
            &[2; 32],
        )
        .unwrap();
        let second = sign_human_escalation(
            &request,
            &session,
            &evidence,
            HumanEscalationDecision::Approve,
            "Independent review confirms the design intent.",
            "HW-42",
            "engineer-b",
            &[3; 32],
        )
        .unwrap();
        let key_a = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
        let key_b = SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes();
        let report = verify_human_escalation(
            &request,
            &session,
            &evidence,
            1_200,
            &[
                HumanEscalationCandidate {
                    escalation: &first,
                    trusted_public_key: &key_a,
                },
                HumanEscalationCandidate {
                    escalation: &second,
                    trusted_public_key: &key_b,
                },
            ],
            HumanEscalationPolicy {
                minimum_approvals: 2,
            },
        )
        .unwrap();
        assert!(report.escalation_eligible);
        assert!(report.escalation_approved);
        assert_eq!(report.approvals, 2);

        let one = verify_human_escalation(
            &request,
            &session,
            &evidence,
            1_200,
            &[HumanEscalationCandidate {
                escalation: &first,
                trusted_public_key: &key_a,
            }],
            HumanEscalationPolicy {
                minimum_approvals: 2,
            },
        )
        .unwrap();
        assert!(!one.escalation_approved);
    }

    #[test]
    fn rejects_replay_tampering_and_non_overridable_ai_failures() {
        let (request, session, mut evidence) = needs_human_evidence();
        let signed = sign_human_escalation(
            &request,
            &session,
            &evidence,
            HumanEscalationDecision::Approve,
            "Reviewed manually.",
            "HW-43",
            "engineer-a",
            &[4; 32],
        )
        .unwrap();
        if let SessionAiQuorumEvidence::Global(report) = &mut evidence {
            report.quorum.members[0].gate_failures =
                vec!["ai_decision_reject".into(), "critical_risk:risk-1".into()];
        }
        assert!(
            sign_human_escalation(
                &request,
                &session,
                &evidence,
                HumanEscalationDecision::Approve,
                "Attempted override.",
                "HW-43",
                "engineer-b",
                &[5; 32],
            )
            .is_err()
        );
        let key = SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes();
        assert!(
            verify_human_escalation(
                &request,
                &session,
                &evidence,
                1_200,
                &[HumanEscalationCandidate {
                    escalation: &signed,
                    trusted_public_key: &key,
                }],
                HumanEscalationPolicy {
                    minimum_approvals: 2,
                },
            )
            .is_err()
        );
        assert!(
            verify_human_escalation(
                &request,
                &session,
                &needs_human_evidence().2,
                2_001,
                &[HumanEscalationCandidate {
                    escalation: &signed,
                    trusted_public_key: &key,
                }],
                HumanEscalationPolicy {
                    minimum_approvals: 2,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn schemas_are_closed() {
        assert_eq!(
            signed_human_escalation_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            human_escalation_report_json_schema()["additionalProperties"],
            false
        );
    }
}
