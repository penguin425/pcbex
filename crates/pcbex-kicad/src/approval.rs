use super::{
    ElectricalPolicy, ElectricalReview, SchematicDocument, SimulationEvidence, check_schematic,
    electrical_policy_json_schema, electrical_review_json_schema, schematic_json_schema,
    simulation_evidence_json_schema, validate_simulation_evidence,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_REQUIREMENTS: usize = 1_000;
const MAX_RISKS: usize = 1_000;
const MAX_EVIDENCE_REFS: usize = 10_000;
const SIGNATURE_DOMAIN: &str = "pcbex-ai-schematic-approval-v1";
const SESSION_SIGNATURE_DOMAIN: &str = "pcbex-ai-schematic-approval-session-v2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRequirement {
    pub id: String,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiApprovalPolicy {
    pub require_simulation_evidence: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewRequest {
    pub schema_version: u32,
    pub request_sha256: String,
    pub schematic: SchematicDocument,
    pub electrical_policy: ElectricalPolicy,
    pub electrical_review: ElectricalReview,
    pub electrical_review_sha256: String,
    pub simulation_evidence: Vec<SimulationEvidence>,
    pub requirements: Vec<AiRequirement>,
    pub evidence_ids: Vec<String>,
    pub approval_policy: AiApprovalPolicy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiReviewDecision {
    Approve,
    Reject,
    NeedsHuman,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiRequirementStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AiRiskSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiModelIdentity {
    pub provider: String,
    pub model: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRequirementAssessment {
    pub id: String,
    pub status: AiRequirementStatus,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiRisk {
    pub id: String,
    pub severity: AiRiskSeverity,
    pub title: String,
    pub rationale: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AiReviewResponse {
    pub schema_version: u32,
    pub request_sha256: String,
    pub model: AiModelIdentity,
    pub decision: AiReviewDecision,
    pub summary: String,
    pub requirements: Vec<AiRequirementAssessment>,
    pub risks: Vec<AiRisk>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAiApproval {
    pub schema_version: u32,
    pub request_sha256: String,
    pub response_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_sha256: Option<String>,
    pub approved: bool,
    pub gate_failures: Vec<String>,
    pub signer_id: String,
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Serialize)]
struct ApprovalPayload<'a> {
    domain: &'static str,
    request_sha256: &'a str,
    response_sha256: &'a str,
    approved: bool,
    gate_failures: &'a [String],
    signer_id: &'a str,
}

#[derive(Serialize)]
struct SessionApprovalPayload<'a> {
    domain: &'static str,
    session_sha256: &'a str,
    request_sha256: &'a str,
    response_sha256: &'a str,
    approved: bool,
    gate_failures: &'a [String],
    signer_id: &'a str,
}

pub fn build_ai_review_request(
    schematic: SchematicDocument,
    policy: &ElectricalPolicy,
    electrical_review: ElectricalReview,
    electrical_review_sha256: String,
    mut simulation_evidence: Vec<SimulationEvidence>,
    mut requirements: Vec<AiRequirement>,
    require_simulation_evidence: bool,
) -> Result<AiReviewRequest, String> {
    validate_sha256(&electrical_review_sha256, "electrical review SHA-256")?;
    let recomputed = check_schematic(&schematic, policy)?;
    if recomputed != electrical_review {
        return Err(
            "electrical review does not match a fresh review of the supplied schematic and policy"
                .into(),
        );
    }
    validate_requirements(&requirements)?;
    requirements.sort_by(|left, right| left.id.cmp(&right.id));

    if simulation_evidence.len() > MAX_REQUIREMENTS {
        return Err(format!(
            "AI review exceeds the {MAX_REQUIREMENTS} simulation-evidence limit"
        ));
    }
    let mut simulation_ids = BTreeSet::new();
    for evidence in &simulation_evidence {
        validate_simulation_evidence(evidence)?;
        if evidence.schematic_sha256 != electrical_review.schematic_sha256 {
            return Err(format!(
                "simulation evidence {} is bound to a different schematic",
                evidence.id
            ));
        }
        if evidence.electrical_review_sha256 != electrical_review_sha256 {
            return Err(format!(
                "simulation evidence {} is bound to a different electrical review",
                evidence.id
            ));
        }
        if !simulation_ids.insert(evidence.id.clone()) {
            return Err(format!("duplicate simulation evidence id {}", evidence.id));
        }
    }
    simulation_evidence.sort_by(|left, right| left.id.cmp(&right.id));

    let evidence_ids = expected_evidence_ids(&schematic, &electrical_review, &simulation_evidence);
    let mut request = AiReviewRequest {
        schema_version: 1,
        request_sha256: String::new(),
        schematic,
        electrical_policy: policy.clone(),
        electrical_review,
        electrical_review_sha256,
        simulation_evidence,
        requirements,
        evidence_ids,
        approval_policy: AiApprovalPolicy {
            require_simulation_evidence,
        },
    };
    request.request_sha256 = request_body_sha256(&request)?;
    Ok(request)
}

pub fn parse_ai_review_response(source: &str) -> Result<AiReviewResponse, String> {
    let value: Value = serde_json::from_str(source)
        .map_err(|error| format!("invalid AI review response: {error}"))?;
    if !value
        .get("model")
        .and_then(Value::as_object)
        .is_some_and(|model| model.contains_key("version"))
    {
        return Err("AI review response model.version is required".into());
    }
    serde_json::from_value(value).map_err(|error| format!("invalid AI review response: {error}"))
}

pub fn ai_review_request_sha256(request: &AiReviewRequest) -> Result<String, String> {
    if request.schema_version != 1 {
        return Err(format!(
            "unsupported AI review request schema version {}",
            request.schema_version
        ));
    }
    validate_request_contents(request)?;
    let expected = request_body_sha256(request)?;
    if request.request_sha256 != expected {
        return Err("AI review request SHA-256 does not match its normalized content".into());
    }
    Ok(expected)
}

fn validate_request_contents(request: &AiReviewRequest) -> Result<(), String> {
    validate_sha256(
        &request.electrical_review_sha256,
        "electrical review SHA-256",
    )?;
    validate_requirements(&request.requirements)?;
    if request
        .requirements
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err("AI review requirements must be sorted by unique id".into());
    }
    let recomputed = check_schematic(&request.schematic, &request.electrical_policy)?;
    if recomputed != request.electrical_review {
        return Err(
            "AI review embeds an electrical result that does not match its schematic and policy"
                .into(),
        );
    }
    let mut simulation_ids = BTreeSet::new();
    for evidence in &request.simulation_evidence {
        validate_simulation_evidence(evidence)?;
        if evidence.schematic_sha256 != request.electrical_review.schematic_sha256
            || evidence.electrical_review_sha256 != request.electrical_review_sha256
        {
            return Err(format!(
                "simulation evidence {} is not bound to this review",
                evidence.id
            ));
        }
        if !simulation_ids.insert(evidence.id.as_str()) {
            return Err(format!("duplicate simulation evidence id {}", evidence.id));
        }
    }
    if request
        .simulation_evidence
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err("simulation evidence must be sorted by unique id".into());
    }
    let expected = expected_evidence_ids(
        &request.schematic,
        &request.electrical_review,
        &request.simulation_evidence,
    );
    if request.evidence_ids != expected {
        return Err("AI review evidence identifiers do not match embedded evidence".into());
    }
    Ok(())
}

fn expected_evidence_ids(
    schematic: &SchematicDocument,
    electrical_review: &ElectricalReview,
    simulation_evidence: &[SimulationEvidence],
) -> Vec<String> {
    let mut evidence_ids = BTreeSet::from(["electrical-review".to_string()]);
    for symbol in &schematic.symbols {
        evidence_ids.insert(format!("symbol:{}", symbol.uuid));
    }
    for net in &schematic.nets {
        evidence_ids.insert(format!("net:{}", net.id));
    }
    for finding in &electrical_review.findings {
        evidence_ids.insert(format!("electrical-finding:{}", finding.id));
    }
    for evidence in simulation_evidence {
        evidence_ids.insert(format!("simulation:{}", evidence.id));
        for assertion in &evidence.assertions {
            evidence_ids.insert(format!(
                "simulation-assertion:{}:{}",
                evidence.id, assertion.id
            ));
        }
    }
    evidence_ids.into_iter().collect()
}

pub fn sign_ai_review(
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedAiApproval, String> {
    validate_nonblank(signer_id, "approval signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let gate_failures = evaluate_ai_review(request, response, &request_sha256)?;
    let response_bytes = serde_json::to_vec(response)
        .map_err(|error| format!("serializing AI review response: {error}"))?;
    let response_sha256 = hex_digest(&response_bytes);
    let approved = gate_failures.is_empty();
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = approval_payload_bytes(
        &request_sha256,
        &response_sha256,
        approved,
        &gate_failures,
        signer_id,
    )?;
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedAiApproval {
        schema_version: 1,
        request_sha256,
        response_sha256,
        session_sha256: None,
        approved,
        gate_failures,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn sign_ai_review_for_session(
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    session_sha256: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedAiApproval, String> {
    validate_sha256(session_sha256, "AI review session SHA-256")?;
    validate_nonblank(signer_id, "approval signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let gate_failures = evaluate_ai_review(request, response, &request_sha256)?;
    let response_sha256 = hex_digest(
        &serde_json::to_vec(response)
            .map_err(|error| format!("serializing AI review response: {error}"))?,
    );
    let approved = gate_failures.is_empty();
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = signing_key.verifying_key().to_bytes();
    let payload = session_approval_payload_bytes(
        session_sha256,
        &request_sha256,
        &response_sha256,
        approved,
        &gate_failures,
        signer_id,
    )?;
    let signature = signing_key.sign(&payload).to_bytes();
    Ok(SignedAiApproval {
        schema_version: 2,
        request_sha256,
        response_sha256,
        session_sha256: Some(session_sha256.into()),
        approved,
        gate_failures,
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key: hex_encode(&public_key),
        signature: hex_encode(&signature),
    })
}

pub fn approval_public_key(secret_key: &[u8; 32]) -> String {
    hex_encode(
        &SigningKey::from_bytes(secret_key)
            .verifying_key()
            .to_bytes(),
    )
}

pub fn verify_signed_ai_approval(
    approval: &SignedAiApproval,
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    match (approval.schema_version, approval.session_sha256.is_some()) {
        (1, false) => {}
        (2, true) => {
            return Err(
                "signed AI approval schema version 2 requires its bound review session".into(),
            );
        }
        (version, _) => {
            return Err(format!(
                "unsupported signed AI approval schema version {version}"
            ));
        }
    }
    verify_signed_ai_approval_inner(approval, request, response, trusted_public_key, None)
}

pub fn verify_session_signed_ai_approval(
    approval: &SignedAiApproval,
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    trusted_public_key: &[u8; 32],
    session_sha256: &str,
) -> Result<(), String> {
    validate_sha256(session_sha256, "AI review session SHA-256")?;
    if approval.schema_version != 2 || approval.session_sha256.as_deref() != Some(session_sha256) {
        return Err("signed AI approval is not bound to the supplied review session".into());
    }
    verify_signed_ai_approval_inner(
        approval,
        request,
        response,
        trusted_public_key,
        Some(session_sha256),
    )
}

fn verify_signed_ai_approval_inner(
    approval: &SignedAiApproval,
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    trusted_public_key: &[u8; 32],
    session_sha256: Option<&str>,
) -> Result<(), String> {
    if approval.algorithm != "ed25519" {
        return Err(format!(
            "unsupported approval signature algorithm {}",
            approval.algorithm
        ));
    }
    validate_nonblank(&approval.signer_id, "approval signer id")?;
    let request_sha256 = ai_review_request_sha256(request)?;
    let response_sha256 = hex_digest(
        &serde_json::to_vec(response)
            .map_err(|error| format!("serializing AI review response: {error}"))?,
    );
    if approval.request_sha256 != request_sha256 || approval.response_sha256 != response_sha256 {
        return Err("signed approval content digests do not match the supplied documents".into());
    }
    let expected_failures = evaluate_ai_review(request, response, &request_sha256)?;
    if approval.gate_failures != expected_failures
        || approval.approved != expected_failures.is_empty()
    {
        return Err("signed approval gate result does not match fresh evaluation".into());
    }
    let public_key = hex_decode_array::<32>(&approval.public_key, "approval public key")?;
    if &public_key != trusted_public_key {
        return Err("approval public key does not match the trusted public key".into());
    }
    let signature = hex_decode_array::<64>(&approval.signature, "approval signature")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid approval public key: {error}"))?;
    let signature = Signature::from_bytes(&signature);
    let payload = if let Some(session_sha256) = session_sha256 {
        session_approval_payload_bytes(
            session_sha256,
            &request_sha256,
            &response_sha256,
            approval.approved,
            &approval.gate_failures,
            &approval.signer_id,
        )?
    } else {
        approval_payload_bytes(
            &request_sha256,
            &response_sha256,
            approval.approved,
            &approval.gate_failures,
            &approval.signer_id,
        )?
    };
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid AI approval signature: {error}"))
}

fn evaluate_ai_review(
    request: &AiReviewRequest,
    response: &AiReviewResponse,
    request_sha256: &str,
) -> Result<Vec<String>, String> {
    if response.schema_version != 1 {
        return Err(format!(
            "unsupported AI review response schema version {}",
            response.schema_version
        ));
    }
    if response.request_sha256 != request_sha256 {
        return Err("AI review response is bound to a different request".into());
    }
    validate_nonblank(&response.model.provider, "AI provider")?;
    validate_nonblank(&response.model.model, "AI model")?;
    if response
        .model
        .version
        .as_deref()
        .is_some_and(|value| value.trim().is_empty())
    {
        return Err("AI model version must not be blank when present".into());
    }
    validate_nonblank(&response.summary, "AI review summary")?;
    if response.risks.len() > MAX_RISKS {
        return Err(format!("AI review exceeds the {MAX_RISKS} risk limit"));
    }
    let valid_evidence = request
        .evidence_ids
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let required_ids = request
        .requirements
        .iter()
        .map(|requirement| requirement.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut assessed_ids = BTreeSet::new();
    for assessment in &response.requirements {
        if !required_ids.contains(assessment.id.as_str()) {
            return Err(format!(
                "AI response assesses unknown requirement {}",
                assessment.id
            ));
        }
        if !assessed_ids.insert(assessment.id.as_str()) {
            return Err(format!(
                "AI response repeats requirement assessment {}",
                assessment.id
            ));
        }
        validate_nonblank(&assessment.rationale, "AI requirement rationale")?;
        validate_evidence_refs(&assessment.evidence_refs, &valid_evidence)?;
    }
    if assessed_ids != required_ids {
        return Err("AI response must assess every requested requirement exactly once".into());
    }
    let mut risk_ids = BTreeSet::new();
    for risk in &response.risks {
        validate_nonblank(&risk.id, "AI risk id")?;
        validate_nonblank(&risk.title, "AI risk title")?;
        validate_nonblank(&risk.rationale, "AI risk rationale")?;
        if !risk_ids.insert(risk.id.as_str()) {
            return Err(format!("AI response repeats risk {}", risk.id));
        }
        validate_evidence_refs(&risk.evidence_refs, &valid_evidence)?;
    }

    let mut failures = Vec::new();
    if !request.electrical_review.approved {
        failures.push("electrical_review_rejected".into());
    }
    if request.approval_policy.require_simulation_evidence && request.simulation_evidence.is_empty()
    {
        failures.push("simulation_evidence_required".into());
    }
    for evidence in &request.simulation_evidence {
        if !evidence.passed {
            failures.push(format!("simulation_evidence_failed:{}", evidence.id));
        }
    }
    match response.decision {
        AiReviewDecision::Approve => {}
        AiReviewDecision::Reject => failures.push("ai_decision_reject".into()),
        AiReviewDecision::NeedsHuman => failures.push("ai_decision_needs_human".into()),
    }
    for assessment in &response.requirements {
        match assessment.status {
            AiRequirementStatus::Pass => {}
            AiRequirementStatus::Fail => {
                failures.push(format!("requirement_failed:{}", assessment.id));
            }
            AiRequirementStatus::Unknown => {
                failures.push(format!("requirement_unknown:{}", assessment.id));
            }
        }
    }
    for risk in &response.risks {
        if risk.severity >= AiRiskSeverity::Error {
            failures.push(format!(
                "risk_{}:{}",
                risk_severity_name(risk.severity),
                risk.id
            ));
        }
    }
    Ok(failures)
}

fn validate_requirements(requirements: &[AiRequirement]) -> Result<(), String> {
    if requirements.is_empty() {
        return Err("AI review requires at least one explicit requirement".into());
    }
    if requirements.len() > MAX_REQUIREMENTS {
        return Err(format!(
            "AI review exceeds the {MAX_REQUIREMENTS} requirement limit"
        ));
    }
    let mut ids = BTreeSet::new();
    for requirement in requirements {
        validate_nonblank(&requirement.id, "AI requirement id")?;
        validate_nonblank(&requirement.text, "AI requirement text")?;
        if !ids.insert(requirement.id.as_str()) {
            return Err(format!("duplicate AI requirement id {}", requirement.id));
        }
    }
    Ok(())
}

fn validate_evidence_refs(refs: &[String], valid: &BTreeSet<&str>) -> Result<(), String> {
    if refs.is_empty() {
        return Err("AI assessments and risks must cite at least one evidence identifier".into());
    }
    if refs.len() > MAX_EVIDENCE_REFS {
        return Err(format!(
            "AI review exceeds the {MAX_EVIDENCE_REFS} evidence-reference limit"
        ));
    }
    let mut seen = BTreeSet::new();
    for reference in refs {
        if !valid.contains(reference.as_str()) {
            return Err(format!(
                "AI response references unknown evidence {reference}"
            ));
        }
        if !seen.insert(reference.as_str()) {
            return Err(format!(
                "AI response repeats evidence reference {reference}"
            ));
        }
    }
    Ok(())
}

fn approval_payload_bytes(
    request_sha256: &str,
    response_sha256: &str,
    approved: bool,
    gate_failures: &[String],
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ApprovalPayload {
        domain: SIGNATURE_DOMAIN,
        request_sha256,
        response_sha256,
        approved,
        gate_failures,
        signer_id,
    })
    .map_err(|error| format!("serializing approval signature payload: {error}"))
}

fn session_approval_payload_bytes(
    session_sha256: &str,
    request_sha256: &str,
    response_sha256: &str,
    approved: bool,
    gate_failures: &[String],
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SessionApprovalPayload {
        domain: SESSION_SIGNATURE_DOMAIN,
        session_sha256,
        request_sha256,
        response_sha256,
        approved,
        gate_failures,
        signer_id,
    })
    .map_err(|error| format!("serializing session approval signature payload: {error}"))
}

fn request_body_sha256(request: &AiReviewRequest) -> Result<String, String> {
    let mut body = request.clone();
    body.request_sha256.clear();
    let bytes = serde_json::to_vec(&body)
        .map_err(|error| format!("serializing AI review request: {error}"))?;
    Ok(hex_digest(&bytes))
}

fn validate_nonblank(value: &str, description: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{description} must not be blank"))
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str, description: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        Err(format!(
            "{description} must be 64 lowercase hexadecimal digits"
        ))
    } else {
        Ok(())
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn hex_decode_array<const N: usize>(value: &str, description: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
    {
        return Err(format!(
            "{description} must be {} hexadecimal digits",
            N * 2
        ));
    }
    let mut result = [0_u8; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| format!("{description} is not hexadecimal"))?;
    }
    Ok(result)
}

fn risk_severity_name(severity: AiRiskSeverity) -> &'static str {
    match severity {
        AiRiskSeverity::Info => "info",
        AiRiskSeverity::Warning => "warning",
        AiRiskSeverity::Error => "error",
        AiRiskSeverity::Critical => "critical",
    }
}

fn string_schema() -> Value {
    json!({"type": "string", "minLength": 1})
}

pub fn ai_review_request_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/ai-review-request-v1.json",
        "title": "pcbex AI schematic review request",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "schematic", "electrical_policy",
            "electrical_review",
            "electrical_review_sha256", "simulation_evidence", "requirements",
            "evidence_ids", "approval_policy"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "schematic": schematic_json_schema(),
            "electrical_policy": electrical_policy_json_schema(),
            "electrical_review": electrical_review_json_schema(),
            "electrical_review_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "simulation_evidence": {
                "type": "array",
                "maxItems": MAX_REQUIREMENTS,
                "items": simulation_evidence_json_schema()
            },
            "requirements": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_REQUIREMENTS,
                "items": {"$ref": "#/$defs/requirement"}
            },
            "evidence_ids": {
                "type": "array",
                "items": string_schema(),
                "uniqueItems": true
            },
            "approval_policy": {"$ref": "#/$defs/policy"}
        },
        "$defs": {
            "requirement": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "text"],
                "properties": {"id": string_schema(), "text": string_schema()}
            },
            "policy": {
                "type": "object",
                "additionalProperties": false,
                "required": ["require_simulation_evidence"],
                "properties": {"require_simulation_evidence": {"type": "boolean"}}
            }
        }
    })
}

pub fn ai_review_response_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/ai-review-response-v1.json",
        "title": "pcbex AI schematic review response",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "model", "decision", "summary",
            "requirements", "risks"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "model": {"$ref": "#/$defs/model"},
            "decision": {"enum": ["approve", "reject", "needs_human"]},
            "summary": string_schema(),
            "requirements": {
                "type": "array",
                "maxItems": MAX_REQUIREMENTS,
                "items": {"$ref": "#/$defs/assessment"}
            },
            "risks": {
                "type": "array",
                "maxItems": MAX_RISKS,
                "items": {"$ref": "#/$defs/risk"}
            }
        },
        "$defs": {
            "model": {
                "type": "object",
                "additionalProperties": false,
                "required": ["provider", "model", "version"],
                "properties": {
                    "provider": string_schema(),
                    "model": string_schema(),
                    "version": {
                        "anyOf": [
                            {"type": "string", "minLength": 1},
                            {"type": "null"}
                        ]
                    }
                }
            },
            "assessment": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "status", "rationale", "evidence_refs"],
                "properties": {
                    "id": string_schema(),
                    "status": {"enum": ["pass", "fail", "unknown"]},
                    "rationale": string_schema(),
                    "evidence_refs": {
                        "type": "array", "minItems": 1, "maxItems": MAX_EVIDENCE_REFS,
                        "uniqueItems": true, "items": string_schema()
                    }
                }
            },
            "risk": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "severity", "title", "rationale", "evidence_refs"],
                "properties": {
                    "id": string_schema(),
                    "severity": {"enum": ["info", "warning", "error", "critical"]},
                    "title": string_schema(),
                    "rationale": string_schema(),
                    "evidence_refs": {
                        "type": "array", "minItems": 1, "maxItems": MAX_EVIDENCE_REFS,
                        "uniqueItems": true, "items": string_schema()
                    }
                }
            }
        }
    })
}

pub fn signed_ai_approval_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/signed-ai-approval-v2.json",
        "title": "pcbex signed AI schematic approval",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "request_sha256", "response_sha256", "approved",
            "gate_failures", "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"enum": [1, 2]},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "session_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "approved": {"type": "boolean"},
            "gate_failures": {"type": "array", "items": string_schema()},
            "signer_id": string_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        },
        "allOf": [
            {
                "if": {"properties": {"schema_version": {"const": 2}}},
                "then": {"required": ["session_sha256"]},
                "else": {"not": {"required": ["session_sha256"]}}
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import_schematic;

    fn approved_request() -> AiReviewRequest {
        let mut schematic =
            import_schematic(include_str!("../../../examples/simple.kicad_sch")).unwrap();
        for symbol in &mut schematic.symbols {
            symbol.dnp = true;
        }
        let policy = ElectricalPolicy::default();
        let review = check_schematic(&schematic, &policy).unwrap();
        build_ai_review_request(
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
        .unwrap()
    }

    fn response(request: &AiReviewRequest) -> AiReviewResponse {
        AiReviewResponse {
            schema_version: 1,
            request_sha256: ai_review_request_sha256(request).unwrap(),
            model: AiModelIdentity {
                provider: "test".into(),
                model: "reviewer".into(),
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
        }
    }

    #[test]
    fn signs_and_strictly_verifies_approved_reviews() {
        let request = approved_request();
        let response = response(&request);
        let approval = sign_ai_review(&request, &response, "ci", &[7; 32]).unwrap();
        assert!(approval.approved);
        assert!(approval.gate_failures.is_empty());
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        verify_signed_ai_approval(&approval, &request, &response, &public_key).unwrap();
        let untrusted_key = SigningKey::from_bytes(&[6; 32]).verifying_key().to_bytes();
        assert!(verify_signed_ai_approval(&approval, &request, &response, &untrusted_key).is_err());
        assert_eq!(
            approval,
            sign_ai_review(&request, &response, "ci", &[7; 32]).unwrap()
        );
    }

    #[test]
    fn session_signatures_cannot_be_replayed_or_downgraded() {
        let request = approved_request();
        let response = response(&request);
        let session = "d".repeat(64);
        let approval =
            sign_ai_review_for_session(&request, &response, &session, "ci", &[7; 32]).unwrap();
        let public_key = SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes();
        verify_session_signed_ai_approval(&approval, &request, &response, &public_key, &session)
            .unwrap();
        assert!(
            verify_session_signed_ai_approval(
                &approval,
                &request,
                &response,
                &public_key,
                &"e".repeat(64),
            )
            .is_err()
        );
        assert!(verify_signed_ai_approval(&approval, &request, &response, &public_key).is_err());
    }

    #[test]
    fn signs_rejections_when_ai_or_requirement_does_not_approve() {
        let request = approved_request();
        let mut response = response(&request);
        response.decision = AiReviewDecision::NeedsHuman;
        response.requirements[0].status = AiRequirementStatus::Unknown;
        let approval = sign_ai_review(&request, &response, "ci", &[8; 32]).unwrap();
        assert!(!approval.approved);
        assert_eq!(
            approval.gate_failures,
            ["ai_decision_needs_human", "requirement_unknown:power"]
        );
        let public_key = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        verify_signed_ai_approval(&approval, &request, &response, &public_key).unwrap();
    }

    #[test]
    fn rejects_missing_assessments_unknown_evidence_and_tampering() {
        let request = approved_request();
        let mut missing_version = serde_json::to_value(response(&request)).unwrap();
        missing_version["model"]
            .as_object_mut()
            .unwrap()
            .remove("version");
        assert!(
            parse_ai_review_response(&serde_json::to_string(&missing_version).unwrap()).is_err()
        );

        let mut invalid = response(&request);
        invalid.requirements.clear();
        assert!(sign_ai_review(&request, &invalid, "ci", &[9; 32]).is_err());

        let mut invalid = response(&request);
        invalid.requirements[0].evidence_refs = vec!["invented".into()];
        assert!(sign_ai_review(&request, &invalid, "ci", &[9; 32]).is_err());

        let response = response(&request);
        let mut approval = sign_ai_review(&request, &response, "ci", &[9; 32]).unwrap();
        approval.signature.replace_range(0..2, "00");
        let public_key = SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        assert!(verify_signed_ai_approval(&approval, &request, &response, &public_key).is_err());

        let mut forged_request = request.clone();
        forged_request.electrical_review.policy_id = "forged".into();
        assert!(ai_review_request_sha256(&forged_request).is_err());
    }

    #[test]
    fn schemas_are_closed() {
        for schema in [
            ai_review_request_json_schema(),
            ai_review_response_json_schema(),
            signed_ai_approval_json_schema(),
        ] {
            assert_eq!(schema["additionalProperties"], false);
            for definition in schema["$defs"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(_, value)| value)
            {
                if definition["type"] == "object" {
                    assert_eq!(definition["additionalProperties"], false);
                }
            }
        }
    }
}
