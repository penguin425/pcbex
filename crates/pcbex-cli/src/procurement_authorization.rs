//! Internal Ed25519 and policy evaluation for exact offline procurement evidence.
//!
//! This module is deliberately not a standalone procurement authority.  The
//! public Python boundary freshly validates the complete assembly and supplier
//! offer evidence before constructing a signing request, and it alone composes
//! the public authorization report.  The Rust helper validates the closed
//! request, policy identity, signatures, commercial scope, and caller-supplied
//! time, then emits only a cryptographic policy assessment.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::policy_pack::{
    OrganizationPolicyPack, ProcurementAuthorizationPolicy, TrustedApprovalKey, policy_pack_sha256,
    validate_policy_pack,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const PROCUREMENT_SIGNING_REQUEST_SCHEMA_VERSION: u32 = 1;
pub(crate) const SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION: u32 = 1;
pub(crate) const PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCHEMA_VERSION: u32 = 1;
pub(crate) const PROCUREMENT_SIGNING_REQUEST_SCOPE: &str =
    "offline-exact-procurement-release-request-v1";
pub(crate) const SIGNED_PROCUREMENT_APPROVAL_SCOPE: &str =
    "offline-exact-procurement-release-approval-v1";
pub(crate) const PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE: &str =
    "offline-exact-procurement-release-cryptographic-assessment-v1";

const ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE: &str =
    "offline-exact-board-assembly-supplier-offer-evidence-v1";
const REQUEST_BINDING_DOMAIN: &[u8] = b"pcbex:offline-exact-procurement-release-request-v1\0";
const APPROVAL_SIGNATURE_DOMAIN: &str = "pcbex-procurement-approval-v1";
const ASSESSMENT_BINDING_DOMAIN: &[u8] =
    b"pcbex:offline-exact-procurement-release-cryptographic-assessment-v1\0";

pub(crate) const MAX_PROCUREMENT_SIGNING_REQUEST_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_SIGNED_PROCUREMENT_APPROVAL_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_PROCUREMENT_POLICY_PACK_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_PROCUREMENT_APPROVALS: usize = 100;
pub(crate) const MAX_PROCUREMENT_APPROVAL_AGGREGATE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES: u64 = 128 * 1024 * 1024;
const MAXIMUM_VALIDITY_SECONDS: u64 = 604_800;
const MAXIMUM_REQUESTED_BOARDS: u32 = 1_000_000;
const MAXIMUM_MONEY_MICROS: u64 = 9_007_199_254_740_991;
const MAXIMUM_TIMESTAMP: u64 = 9_223_372_036_854_775_807;
const MAXIMUM_REASON_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;
const MAXIMUM_SUPPLIER_BYTES: usize = 64;
const MAXIMUM_OFFER_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProcurementApprovalDecision {
    Approve,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAssemblyEvidenceProjection {
    pub(crate) source: ExactArtifactIdentity,
    pub(crate) binding_sha256: String,
    pub(crate) schema_version: u32,
    pub(crate) scope: String,
    pub(crate) complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementCommercialEvidence {
    pub(crate) requested_boards: u32,
    pub(crate) supplier: String,
    pub(crate) offer_id: String,
    pub(crate) currency: String,
    pub(crate) covered: bool,
    pub(crate) component_subtotal_micros: Option<u64>,
    pub(crate) offer_valid_from_unix: u64,
    pub(crate) offer_valid_until_unix: u64,
    pub(crate) receipt_fetched_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementPolicyPackProjection {
    pub(crate) source: ExactArtifactIdentity,
    pub(crate) canonical_sha256: String,
    pub(crate) id: String,
    pub(crate) revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAuthorizationEvidence {
    pub(crate) assembly_supplier_offer_evidence: ProcurementAssemblyEvidenceProjection,
    pub(crate) commercial: ProcurementCommercialEvidence,
    pub(crate) policy_pack: ProcurementPolicyPackProjection,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAuthorizationScope {
    pub(crate) authorization_id: String,
    pub(crate) challenge: String,
    pub(crate) requested_boards: u32,
    pub(crate) currency: String,
    pub(crate) maximum_component_subtotal_micros: u64,
    pub(crate) valid_from_unix: u64,
    pub(crate) expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementApprovalSigningRequest {
    pub(crate) schema_version: u32,
    pub(crate) scope: String,
    pub(crate) evidence: ProcurementAuthorizationEvidence,
    pub(crate) authorization_scope: ProcurementAuthorizationScope,
    pub(crate) binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedProcurementApproval {
    pub(crate) schema_version: u32,
    pub(crate) scope: String,
    pub(crate) evidence: ProcurementAuthorizationEvidence,
    pub(crate) authorization_scope: ProcurementAuthorizationScope,
    pub(crate) decision: ProcurementApprovalDecision,
    pub(crate) reason: String,
    pub(crate) ticket: String,
    pub(crate) signer_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAuthorizationMember {
    pub(crate) signer_id: String,
    pub(crate) public_key: String,
    pub(crate) approval_sha256: String,
    pub(crate) decision: ProcurementApprovalDecision,
    pub(crate) reason: String,
    pub(crate) ticket: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementAssessmentValidation {
    pub(crate) request_binding_validated: bool,
    pub(crate) commercial_scope_cross_bound: bool,
    pub(crate) policy_pack_validated: bool,
    pub(crate) approval_signatures_verified: bool,
    pub(crate) distinct_signers_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcurementCryptographicAssessment {
    pub(crate) schema_version: u32,
    pub(crate) scope: String,
    pub(crate) status: String,
    pub(crate) policy_satisfied: bool,
    pub(crate) evidence: ProcurementAuthorizationEvidence,
    pub(crate) authorization_scope: ProcurementAuthorizationScope,
    pub(crate) policy_pack: OrganizationPolicyPack,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) approvals: u32,
    pub(crate) rejections: u32,
    pub(crate) members: Vec<ProcurementAuthorizationMember>,
    pub(crate) signed_approvals: Vec<SignedProcurementApproval>,
    pub(crate) gate_failures: Vec<String>,
    pub(crate) validation: ProcurementAssessmentValidation,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct RequestBindingPayload<'a> {
    schema_version: u32,
    scope: &'a str,
    evidence: &'a ProcurementAuthorizationEvidence,
    authorization_scope: &'a ProcurementAuthorizationScope,
}

#[derive(Serialize)]
struct ApprovalSignaturePayload<'a> {
    domain: &'static str,
    schema_version: u32,
    scope: &'a str,
    evidence: &'a ProcurementAuthorizationEvidence,
    authorization_scope: &'a ProcurementAuthorizationScope,
    decision: ProcurementApprovalDecision,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
    algorithm: &'a str,
    public_key: &'a str,
}

#[derive(Serialize)]
struct AssessmentBindingPayload<'a> {
    schema_version: u32,
    scope: &'a str,
    status: &'a str,
    policy_satisfied: bool,
    evidence: &'a ProcurementAuthorizationEvidence,
    authorization_scope: &'a ProcurementAuthorizationScope,
    policy_pack: &'a OrganizationPolicyPack,
    evaluated_at_unix: u64,
    approvals: u32,
    rejections: u32,
    members: &'a [ProcurementAuthorizationMember],
    signed_approvals: &'a [SignedProcurementApproval],
    gate_failures: &'a [String],
    validation: &'a ProcurementAssessmentValidation,
}

pub(crate) fn parse_procurement_approval_signing_request(
    source: &[u8],
) -> Result<ProcurementApprovalSigningRequest, String> {
    validate_source_size(
        source,
        MAX_PROCUREMENT_SIGNING_REQUEST_BYTES,
        "procurement approval signing request",
    )?;
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid procurement approval signing request JSON: {error:#}"))?;
    let request: ProcurementApprovalSigningRequest = serde_json::from_slice(source)
        .map_err(|error| format!("invalid procurement approval signing request JSON: {error}"))?;
    validate_procurement_approval_signing_request(&request)?;
    Ok(request)
}

pub(crate) fn validate_procurement_approval_signing_request(
    request: &ProcurementApprovalSigningRequest,
) -> Result<(), String> {
    if request.schema_version != PROCUREMENT_SIGNING_REQUEST_SCHEMA_VERSION {
        return Err(format!(
            "unsupported procurement approval signing request schema_version {}; expected {}",
            request.schema_version, PROCUREMENT_SIGNING_REQUEST_SCHEMA_VERSION
        ));
    }
    if request.scope != PROCUREMENT_SIGNING_REQUEST_SCOPE {
        return Err(format!(
            "unsupported procurement approval signing request scope {:?}",
            request.scope
        ));
    }
    validate_procurement_evidence(&request.evidence)?;
    validate_procurement_authorization_scope(&request.authorization_scope)?;
    validate_commercial_scope_cross_binding(
        &request.evidence.commercial,
        &request.authorization_scope,
    )?;
    validate_digest(
        &request.binding_sha256,
        "procurement signing request binding",
    )?;
    let expected = request_binding_sha256(request)?;
    if request.binding_sha256 != expected {
        return Err(
            "procurement approval signing request binding does not match its fields".into(),
        );
    }
    Ok(())
}

pub(crate) fn request_binding_sha256(
    request: &ProcurementApprovalSigningRequest,
) -> Result<String, String> {
    let payload = serde_json::to_vec(&RequestBindingPayload {
        schema_version: request.schema_version,
        scope: &request.scope,
        evidence: &request.evidence,
        authorization_scope: &request.authorization_scope,
    })
    .map_err(|error| format!("serializing procurement signing request binding: {error}"))?;
    Ok(domain_separated_sha256(REQUEST_BINDING_DOMAIN, &payload))
}

pub(crate) fn parse_and_bind_procurement_policy_pack(
    policy_source: &[u8],
    expected_canonical_sha256: &str,
    evidence: &ProcurementPolicyPackProjection,
) -> Result<OrganizationPolicyPack, String> {
    validate_source_size(
        policy_source,
        MAX_PROCUREMENT_POLICY_PACK_BYTES,
        "organization policy pack",
    )?;
    validate_digest(
        expected_canonical_sha256,
        "expected canonical organization policy pack SHA-256",
    )?;
    let actual_source = exact_identity(policy_source);
    if actual_source != evidence.source {
        return Err(
            "organization policy pack source does not match the signing request identity".into(),
        );
    }
    reject_duplicate_json_keys(policy_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error:#}"))?;
    let pack: OrganizationPolicyPack = serde_json::from_slice(policy_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error}"))?;
    validate_policy_pack(&pack)?;
    if pack.procurement_authorization_policy.is_none() {
        return Err("organization policy pack has no procurement authorization policy".into());
    }
    let canonical_sha256 = policy_pack_sha256(&pack)?;
    if canonical_sha256 != expected_canonical_sha256 {
        return Err(
            "organization policy pack does not match the mandatory expected canonical digest pin"
                .into(),
        );
    }
    if evidence.canonical_sha256 != canonical_sha256
        || evidence.id != pack.id
        || evidence.revision != pack.revision
    {
        return Err(
            "procurement evidence does not bind the supplied organization policy pack".into(),
        );
    }
    Ok(pack)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_procurement_approval_signing_inputs(
    request: &ProcurementApprovalSigningRequest,
    policy_pack: &OrganizationPolicyPack,
    decision: ProcurementApprovalDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<(), String> {
    validate_procurement_approval_signing_request(request)?;
    let policy = validate_bound_procurement_policy(&request.evidence, policy_pack)?;
    validate_text(reason, MAXIMUM_REASON_BYTES, "procurement approval reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "procurement approval ticket")?;
    validate_slug("procurement approval signer", signer_id)?;
    trusted_procurement_signer(policy, signer_id)?;
    if decision == ProcurementApprovalDecision::Approve
        && (!request.evidence.assembly_supplier_offer_evidence.complete
            || !request.evidence.commercial.covered
            || request
                .evidence
                .commercial
                .component_subtotal_micros
                .is_none())
    {
        return Err(
            "cannot approve incomplete or uncovered procurement evidence without a component subtotal"
                .into(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_procurement_approval(
    request: &ProcurementApprovalSigningRequest,
    policy_pack: &OrganizationPolicyPack,
    decision: ProcurementApprovalDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedProcurementApproval, String> {
    validate_procurement_approval_signing_inputs(
        request,
        policy_pack,
        decision,
        reason,
        ticket,
        signer_id,
    )?;
    let policy = policy_pack
        .procurement_authorization_policy
        .as_ref()
        .expect("validated procurement policy is present");
    let trusted = trusted_procurement_signer(policy, signer_id)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if public_key != trusted.public_key {
        return Err(
            "procurement approval private key does not match the signer's trusted key".into(),
        );
    }
    let mut signed = SignedProcurementApproval {
        schema_version: SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION,
        scope: SIGNED_PROCUREMENT_APPROVAL_SCOPE.into(),
        evidence: request.evidence.clone(),
        authorization_scope: request.authorization_scope.clone(),
        decision,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: String::new(),
    };
    let payload = approval_signature_payload(&signed)?;
    signed.signature = hex::encode(signing_key.sign(&payload).to_bytes());
    validate_signed_procurement_approval(&signed)?;
    Ok(signed)
}

pub(crate) fn parse_signed_procurement_approval(
    source: &[u8],
) -> Result<SignedProcurementApproval, String> {
    validate_source_size(
        source,
        MAX_SIGNED_PROCUREMENT_APPROVAL_BYTES,
        "signed procurement approval",
    )?;
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid signed procurement approval JSON: {error:#}"))?;
    let signed: SignedProcurementApproval = serde_json::from_slice(source)
        .map_err(|error| format!("invalid signed procurement approval JSON: {error}"))?;
    validate_signed_procurement_approval(&signed)?;
    Ok(signed)
}

pub(crate) fn validate_signed_procurement_approval(
    signed: &SignedProcurementApproval,
) -> Result<(), String> {
    if signed.schema_version != SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION {
        return Err(format!(
            "unsupported signed procurement approval schema_version {}; expected {}",
            signed.schema_version, SIGNED_PROCUREMENT_APPROVAL_SCHEMA_VERSION
        ));
    }
    if signed.scope != SIGNED_PROCUREMENT_APPROVAL_SCOPE {
        return Err(format!(
            "unsupported signed procurement approval scope {:?}",
            signed.scope
        ));
    }
    validate_procurement_evidence(&signed.evidence)?;
    validate_procurement_authorization_scope(&signed.authorization_scope)?;
    validate_commercial_scope_cross_binding(
        &signed.evidence.commercial,
        &signed.authorization_scope,
    )?;
    validate_text(
        &signed.reason,
        MAXIMUM_REASON_BYTES,
        "procurement approval reason",
    )?;
    validate_text(
        &signed.ticket,
        MAXIMUM_TICKET_BYTES,
        "procurement approval ticket",
    )?;
    validate_slug("procurement approval signer", &signed.signer_id)?;
    if signed.algorithm != "ed25519" {
        return Err(format!(
            "unsupported procurement approval signature algorithm {:?}",
            signed.algorithm
        ));
    }
    decode_hex_array::<32>(&signed.public_key, "procurement approval public key")?;
    decode_hex_array::<64>(&signed.signature, "procurement approval signature")?;
    Ok(())
}

pub(crate) fn verify_procurement_cryptographic_assessment(
    request: &ProcurementApprovalSigningRequest,
    policy_pack: &OrganizationPolicyPack,
    signed_approvals: &[SignedProcurementApproval],
    evaluated_at_unix: u64,
) -> Result<ProcurementCryptographicAssessment, String> {
    validate_procurement_approval_signing_request(request)?;
    validate_timestamp(evaluated_at_unix, "procurement evaluation timestamp")?;
    let policy = validate_bound_procurement_policy(&request.evidence, policy_pack)?;
    if signed_approvals.is_empty() || signed_approvals.len() > MAX_PROCUREMENT_APPROVALS {
        return Err(format!(
            "procurement approval set must contain 1 to {MAX_PROCUREMENT_APPROVALS} entries"
        ));
    }

    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut retained = Vec::with_capacity(signed_approvals.len());
    for signed in signed_approvals {
        validate_signed_procurement_approval(signed)?;
        if signed.evidence != request.evidence {
            return Err("procurement approvals do not bind the exact request evidence".into());
        }
        if signed.authorization_scope != request.authorization_scope {
            return Err(
                "procurement approvals do not bind the exact request authorization scope".into(),
            );
        }
        let trusted = trusted_procurement_signer(policy, &signed.signer_id)?;
        verify_approval_signature(
            signed,
            &decode_hex_array::<32>(&trusted.public_key, "trusted procurement public key")?,
        )?;
        if !signer_ids.insert(signed.signer_id.as_str())
            || !public_keys.insert(signed.public_key.as_str())
        {
            return Err(
                "procurement approvals require distinct trusted signer IDs and keys".into(),
            );
        }
        retained.push(signed.clone());
    }

    retained.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let approvals = retained
        .iter()
        .filter(|signed| signed.decision == ProcurementApprovalDecision::Approve)
        .count() as u32;
    let rejections = retained.len() as u32 - approvals;
    let gate_failures = procurement_gate_failures(
        &request.evidence,
        &request.authorization_scope,
        policy,
        approvals,
        rejections,
        evaluated_at_unix,
    );
    let policy_satisfied = gate_failures.is_empty();
    let members = retained
        .iter()
        .map(procurement_member)
        .collect::<Result<Vec<_>, _>>()?;
    let validation = ProcurementAssessmentValidation {
        request_binding_validated: true,
        commercial_scope_cross_bound: true,
        policy_pack_validated: true,
        approval_signatures_verified: true,
        distinct_signers_verified: true,
    };
    let mut assessment = ProcurementCryptographicAssessment {
        schema_version: PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCHEMA_VERSION,
        scope: PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE.into(),
        status: if policy_satisfied {
            "policy_satisfied"
        } else {
            "not_satisfied"
        }
        .into(),
        policy_satisfied,
        evidence: request.evidence.clone(),
        authorization_scope: request.authorization_scope.clone(),
        policy_pack: policy_pack.clone(),
        evaluated_at_unix,
        approvals,
        rejections,
        members,
        signed_approvals: retained,
        gate_failures,
        validation,
        binding_sha256: String::new(),
    };
    assessment.binding_sha256 = assessment_binding_sha256(&assessment)?;
    validate_procurement_cryptographic_assessment(&assessment)?;
    Ok(assessment)
}

pub(crate) fn validate_procurement_cryptographic_assessment(
    assessment: &ProcurementCryptographicAssessment,
) -> Result<(), String> {
    if assessment.schema_version != PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCHEMA_VERSION
        || assessment.scope != PROCUREMENT_CRYPTOGRAPHIC_ASSESSMENT_SCOPE
        || !matches!(
            assessment.status.as_str(),
            "policy_satisfied" | "not_satisfied"
        )
    {
        return Err("procurement cryptographic assessment identity is invalid".into());
    }
    validate_procurement_evidence(&assessment.evidence)?;
    validate_timestamp(
        assessment.evaluated_at_unix,
        "procurement assessment evaluation timestamp",
    )?;
    validate_procurement_authorization_scope(&assessment.authorization_scope)?;
    validate_commercial_scope_cross_binding(
        &assessment.evidence.commercial,
        &assessment.authorization_scope,
    )?;
    let policy = validate_bound_procurement_policy(&assessment.evidence, &assessment.policy_pack)?;
    if assessment.signed_approvals.is_empty()
        || assessment.signed_approvals.len() > MAX_PROCUREMENT_APPROVALS
        || assessment.members.len() != assessment.signed_approvals.len()
        || assessment.approvals.checked_add(assessment.rejections)
            != Some(assessment.signed_approvals.len() as u32)
        || assessment.validation
            != (ProcurementAssessmentValidation {
                request_binding_validated: true,
                commercial_scope_cross_bound: true,
                policy_pack_validated: true,
                approval_signatures_verified: true,
                distinct_signers_verified: true,
            })
    {
        return Err("procurement cryptographic assessment counts or validation are invalid".into());
    }

    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut previous_signer: Option<&str> = None;
    let mut approvals = 0_u32;
    let mut expected_members = Vec::with_capacity(assessment.signed_approvals.len());
    for signed in &assessment.signed_approvals {
        validate_signed_procurement_approval(signed)?;
        if signed.evidence != assessment.evidence
            || signed.authorization_scope != assessment.authorization_scope
            || previous_signer.is_some_and(|previous| previous >= signed.signer_id.as_str())
        {
            return Err("procurement assessment approvals are inconsistent or unordered".into());
        }
        let trusted = trusted_procurement_signer(policy, &signed.signer_id)?;
        verify_approval_signature(
            signed,
            &decode_hex_array::<32>(
                &trusted.public_key,
                "retained trusted procurement public key",
            )?,
        )?;
        if !signer_ids.insert(signed.signer_id.as_str())
            || !public_keys.insert(signed.public_key.as_str())
        {
            return Err("procurement assessment signatures are not independent".into());
        }
        approvals += u32::from(signed.decision == ProcurementApprovalDecision::Approve);
        previous_signer = Some(signed.signer_id.as_str());
        expected_members.push(procurement_member(signed)?);
    }
    let rejections = assessment.signed_approvals.len() as u32 - approvals;
    let expected_failures = procurement_gate_failures(
        &assessment.evidence,
        &assessment.authorization_scope,
        policy,
        approvals,
        rejections,
        assessment.evaluated_at_unix,
    );
    let expected_satisfied = expected_failures.is_empty();
    if assessment.approvals != approvals
        || assessment.rejections != rejections
        || assessment.members != expected_members
        || assessment.gate_failures != expected_failures
        || assessment.policy_satisfied != expected_satisfied
        || assessment.status
            != if expected_satisfied {
                "policy_satisfied"
            } else {
                "not_satisfied"
            }
    {
        return Err("procurement cryptographic assessment outcome is inconsistent".into());
    }
    validate_digest(
        &assessment.binding_sha256,
        "procurement cryptographic assessment binding",
    )?;
    if assessment.binding_sha256 != assessment_binding_sha256(assessment)? {
        return Err("procurement cryptographic assessment binding is invalid".into());
    }
    Ok(())
}

pub(crate) fn assessment_binding_sha256(
    assessment: &ProcurementCryptographicAssessment,
) -> Result<String, String> {
    let payload = serde_json::to_vec(&AssessmentBindingPayload {
        schema_version: assessment.schema_version,
        scope: &assessment.scope,
        status: &assessment.status,
        policy_satisfied: assessment.policy_satisfied,
        evidence: &assessment.evidence,
        authorization_scope: &assessment.authorization_scope,
        policy_pack: &assessment.policy_pack,
        evaluated_at_unix: assessment.evaluated_at_unix,
        approvals: assessment.approvals,
        rejections: assessment.rejections,
        members: &assessment.members,
        signed_approvals: &assessment.signed_approvals,
        gate_failures: &assessment.gate_failures,
        validation: &assessment.validation,
    })
    .map_err(|error| format!("serializing procurement assessment binding: {error}"))?;
    Ok(domain_separated_sha256(ASSESSMENT_BINDING_DOMAIN, &payload))
}

fn validate_bound_procurement_policy<'a>(
    evidence: &ProcurementAuthorizationEvidence,
    policy_pack: &'a OrganizationPolicyPack,
) -> Result<&'a ProcurementAuthorizationPolicy, String> {
    validate_policy_pack(policy_pack)?;
    let policy = policy_pack
        .procurement_authorization_policy
        .as_ref()
        .ok_or_else(|| {
            "organization policy pack has no procurement authorization policy".to_string()
        })?;
    if evidence.policy_pack.canonical_sha256 != policy_pack_sha256(policy_pack)?
        || evidence.policy_pack.id != policy_pack.id
        || evidence.policy_pack.revision != policy_pack.revision
    {
        return Err("procurement evidence does not bind the retained policy pack".into());
    }
    if evidence.commercial.currency != policy.currency {
        return Err("procurement commercial currency does not match policy currency".into());
    }
    Ok(policy)
}

fn trusted_procurement_signer<'a>(
    policy: &'a ProcurementAuthorizationPolicy,
    signer_id: &str,
) -> Result<&'a TrustedApprovalKey, String> {
    policy
        .trusted_keys
        .iter()
        .find(|trusted| trusted.signer_id == signer_id)
        .ok_or_else(|| {
            format!("procurement signer {signer_id:?} is not trusted by the organization policy")
        })
}

fn verify_approval_signature(
    signed: &SignedProcurementApproval,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    let public_key = decode_hex_array::<32>(&signed.public_key, "procurement approval public key")?;
    if &public_key != trusted_public_key {
        return Err("procurement approval public key does not match its trusted key".into());
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid procurement approval public key: {error}"))?;
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &signed.signature,
        "procurement approval signature",
    )?);
    let payload = approval_signature_payload(signed)?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid procurement approval signature: {error}"))
}

fn approval_signature_payload(signed: &SignedProcurementApproval) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ApprovalSignaturePayload {
        domain: APPROVAL_SIGNATURE_DOMAIN,
        schema_version: signed.schema_version,
        scope: &signed.scope,
        evidence: &signed.evidence,
        authorization_scope: &signed.authorization_scope,
        decision: signed.decision,
        reason: &signed.reason,
        ticket: &signed.ticket,
        signer_id: &signed.signer_id,
        algorithm: &signed.algorithm,
        public_key: &signed.public_key,
    })
    .map_err(|error| format!("serializing procurement approval signature payload: {error}"))
}

fn procurement_member(
    signed: &SignedProcurementApproval,
) -> Result<ProcurementAuthorizationMember, String> {
    Ok(ProcurementAuthorizationMember {
        signer_id: signed.signer_id.clone(),
        public_key: signed.public_key.clone(),
        approval_sha256: canonical_json_sha256(signed, "signed procurement approval")?,
        decision: signed.decision,
        reason: signed.reason.clone(),
        ticket: signed.ticket.clone(),
    })
}

fn procurement_gate_failures(
    evidence: &ProcurementAuthorizationEvidence,
    scope: &ProcurementAuthorizationScope,
    policy: &ProcurementAuthorizationPolicy,
    approvals: u32,
    rejections: u32,
    evaluated_at_unix: u64,
) -> Vec<String> {
    let commercial = &evidence.commercial;
    let mut failures = Vec::new();
    if !evidence.assembly_supplier_offer_evidence.complete {
        failures.push("evidence_incomplete".into());
    }
    if !commercial.covered || commercial.component_subtotal_micros.is_none() {
        failures.push("supplier_offer_not_covered".into());
    }
    if evaluated_at_unix < scope.valid_from_unix || evaluated_at_unix > scope.expires_at_unix {
        failures.push("approval_window_inactive".into());
    }
    if evaluated_at_unix < commercial.offer_valid_from_unix
        || evaluated_at_unix >= commercial.offer_valid_until_unix
    {
        failures.push("offer_window_inactive".into());
    }
    if commercial.receipt_fetched_at_unix > evaluated_at_unix {
        failures.push("receipt_observation_from_future".into());
    } else {
        let age = evaluated_at_unix - commercial.receipt_fetched_at_unix;
        if age > policy.maximum_receipt_observation_age_seconds {
            failures.push(format!(
                "receipt_observation_too_old:maximum_seconds={}:actual_seconds={age}",
                policy.maximum_receipt_observation_age_seconds
            ));
        }
    }
    if let Some(actual) = commercial.component_subtotal_micros
        && actual > scope.maximum_component_subtotal_micros
    {
        failures.push(format!(
            "component_subtotal_exceeds_signed_ceiling:maximum_micros={}:actual_micros={actual}",
            scope.maximum_component_subtotal_micros
        ));
    }
    if scope.maximum_component_subtotal_micros > policy.maximum_component_subtotal_micros {
        failures.push(format!(
            "signed_component_subtotal_ceiling_exceeds_policy:maximum_micros={}:actual_micros={}",
            policy.maximum_component_subtotal_micros, scope.maximum_component_subtotal_micros
        ));
    }
    let duration = scope.expires_at_unix - scope.valid_from_unix;
    if duration > policy.maximum_validity_seconds {
        failures.push(format!(
            "procurement_validity_exceeds_policy:maximum_seconds={}:actual_seconds={duration}",
            policy.maximum_validity_seconds
        ));
    }
    if approvals < policy.minimum_approvals {
        failures.push(format!(
            "insufficient_procurement_approvals:required={}:actual={approvals}",
            policy.minimum_approvals
        ));
    }
    if rejections > 0 {
        failures.push(format!("human_rejection:count={rejections}"));
    }
    failures.sort();
    failures
}

fn validate_procurement_evidence(
    evidence: &ProcurementAuthorizationEvidence,
) -> Result<(), String> {
    let assembly = &evidence.assembly_supplier_offer_evidence;
    validate_artifact_identity(
        &assembly.source,
        MAX_ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_BYTES,
        "assembly supplier-offer evidence source",
    )?;
    validate_digest(
        &assembly.binding_sha256,
        "assembly supplier-offer evidence binding",
    )?;
    if assembly.schema_version != 1 || assembly.scope != ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE {
        return Err("assembly supplier-offer evidence projection identity is invalid".into());
    }

    let commercial = &evidence.commercial;
    if commercial.requested_boards == 0 || commercial.requested_boards > MAXIMUM_REQUESTED_BOARDS {
        return Err(format!(
            "procurement requested_boards must be between 1 and {MAXIMUM_REQUESTED_BOARDS}"
        ));
    }
    validate_supplier(&commercial.supplier)?;
    validate_canonical_text(
        &commercial.offer_id,
        MAXIMUM_OFFER_ID_BYTES,
        "procurement offer id",
    )?;
    validate_currency(&commercial.currency, "procurement commercial currency")?;
    if commercial.covered != commercial.component_subtotal_micros.is_some() {
        return Err(
            "procurement offer covered status and component subtotal presence disagree".into(),
        );
    }
    if commercial
        .component_subtotal_micros
        .is_some_and(|value| value > MAXIMUM_MONEY_MICROS)
    {
        return Err(format!(
            "procurement component subtotal cannot exceed {MAXIMUM_MONEY_MICROS} micros"
        ));
    }
    if commercial.offer_valid_from_unix >= commercial.offer_valid_until_unix {
        return Err("procurement supplier offer validity interval is invalid".into());
    }
    validate_timestamp(
        commercial.offer_valid_from_unix,
        "procurement supplier offer valid-from timestamp",
    )?;
    validate_timestamp(
        commercial.offer_valid_until_unix,
        "procurement supplier offer valid-until timestamp",
    )?;
    validate_timestamp(
        commercial.receipt_fetched_at_unix,
        "procurement receipt observation timestamp",
    )?;

    validate_artifact_identity(
        &evidence.policy_pack.source,
        MAX_PROCUREMENT_POLICY_PACK_BYTES,
        "procurement policy pack source",
    )?;
    validate_digest(
        &evidence.policy_pack.canonical_sha256,
        "canonical procurement policy pack SHA-256",
    )?;
    validate_slug("procurement policy pack id", &evidence.policy_pack.id)?;
    if evidence.policy_pack.revision == 0 {
        return Err("procurement policy pack revision must be greater than zero".into());
    }
    Ok(())
}

fn validate_procurement_authorization_scope(
    scope: &ProcurementAuthorizationScope,
) -> Result<(), String> {
    validate_slug("procurement authorization id", &scope.authorization_id)?;
    validate_digest(&scope.challenge, "procurement authorization challenge")?;
    if scope.requested_boards == 0 || scope.requested_boards > MAXIMUM_REQUESTED_BOARDS {
        return Err(format!(
            "procurement authorization requested_boards must be between 1 and {MAXIMUM_REQUESTED_BOARDS}"
        ));
    }
    validate_currency(&scope.currency, "procurement authorization currency")?;
    validate_timestamp(
        scope.valid_from_unix,
        "procurement authorization valid-from timestamp",
    )?;
    validate_timestamp(
        scope.expires_at_unix,
        "procurement authorization expiry timestamp",
    )?;
    if scope.maximum_component_subtotal_micros == 0
        || scope.maximum_component_subtotal_micros > MAXIMUM_MONEY_MICROS
    {
        return Err(format!(
            "procurement authorization component subtotal ceiling must be between 1 and {MAXIMUM_MONEY_MICROS} micros"
        ));
    }
    let duration = scope
        .expires_at_unix
        .checked_sub(scope.valid_from_unix)
        .ok_or_else(|| "procurement authorization expiry precedes validity".to_string())?;
    if duration == 0 || duration > MAXIMUM_VALIDITY_SECONDS {
        return Err(format!(
            "procurement authorization window must be 1 to {MAXIMUM_VALIDITY_SECONDS} seconds"
        ));
    }
    Ok(())
}

fn validate_commercial_scope_cross_binding(
    commercial: &ProcurementCommercialEvidence,
    scope: &ProcurementAuthorizationScope,
) -> Result<(), String> {
    if commercial.requested_boards != scope.requested_boards {
        return Err(
            "procurement authorization requested_boards does not match commercial evidence".into(),
        );
    }
    if commercial.currency != scope.currency {
        return Err("procurement authorization currency does not match commercial evidence".into());
    }
    if scope.valid_from_unix < commercial.offer_valid_from_unix
        || scope.expires_at_unix >= commercial.offer_valid_until_unix
    {
        return Err(
            "procurement authorization window must be contained in the supplier offer interval"
                .into(),
        );
    }
    Ok(())
}

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

fn domain_separated_sha256(domain: &[u8], payload: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(payload);
    hex::encode(digest.finalize())
}

fn canonical_json_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing canonical {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn validate_source_size(source: &[u8], maximum_bytes: u64, label: &str) -> Result<(), String> {
    if source.is_empty() || source.len() as u64 > maximum_bytes {
        return Err(format!("{label} must contain 1 to {maximum_bytes} bytes"));
    }
    Ok(())
}

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    maximum_bytes: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum_bytes {
        return Err(format!(
            "{label} identity must contain 1 to {maximum_bytes} bytes"
        ));
    }
    validate_digest(&identity.sha256, &format!("{label} SHA-256"))
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        ));
    }
    Ok(())
}

fn validate_slug(label: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'-'))
        });
    if !valid {
        return Err(format!(
            "{label} {value:?} must match [a-z0-9][a-z0-9.-]{{0,127}}"
        ));
    }
    Ok(())
}

fn validate_supplier(value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= MAXIMUM_SUPPLIER_BYTES
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && (bytes[bytes.len() - 1].is_ascii_lowercase() || bytes[bytes.len() - 1].is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if !valid {
        return Err("procurement supplier identifier is invalid".into());
    }
    Ok(())
}

fn validate_currency(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 3 || !value.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(format!(
            "{label} must contain exactly three uppercase ASCII letters"
        ));
    }
    Ok(())
}

fn validate_timestamp(value: u64, label: &str) -> Result<(), String> {
    if value > MAXIMUM_TIMESTAMP {
        return Err(format!("{label} cannot exceed {MAXIMUM_TIMESTAMP}"));
    }
    Ok(())
}

fn validate_canonical_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(|character| character < '\u{20}')
    {
        return Err(format!(
            "{label} must contain 1 to {maximum} canonical UTF-8 bytes"
        ));
    }
    Ok(())
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(format!("{label} must contain 1 to {maximum} UTF-8 bytes"));
    }
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must contain {} lowercase hexadecimal digits",
            N * 2
        ));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_pack::{
        ProcurementAuthorizationPolicy, TrustedApprovalKey, parse_policy_pack,
    };

    fn policy() -> OrganizationPolicyPack {
        let mut pack =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        pack.procurement_authorization_policy = Some(ProcurementAuthorizationPolicy {
            minimum_approvals: 2,
            currency: "USD".into(),
            maximum_validity_seconds: 3_600,
            maximum_receipt_observation_age_seconds: 300,
            maximum_component_subtotal_micros: 2_000_000,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "procurement-a".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[51; 32]).verifying_key().to_bytes(),
                    ),
                },
                TrustedApprovalKey {
                    signer_id: "procurement-b".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes(),
                    ),
                },
            ],
        });
        validate_policy_pack(&pack).unwrap();
        pack
    }

    fn policy_source(pack: &OrganizationPolicyPack) -> Vec<u8> {
        let mut source = serde_json::to_vec_pretty(pack).unwrap();
        source.push(b'\n');
        source
    }

    fn sample_request(pack: &OrganizationPolicyPack) -> ProcurementApprovalSigningRequest {
        let source = policy_source(pack);
        let mut request = ProcurementApprovalSigningRequest {
            schema_version: PROCUREMENT_SIGNING_REQUEST_SCHEMA_VERSION,
            scope: PROCUREMENT_SIGNING_REQUEST_SCOPE.into(),
            evidence: ProcurementAuthorizationEvidence {
                assembly_supplier_offer_evidence: ProcurementAssemblyEvidenceProjection {
                    source: ExactArtifactIdentity {
                        bytes: 123,
                        sha256: "a".repeat(64),
                    },
                    binding_sha256: "b".repeat(64),
                    schema_version: 1,
                    scope: ASSEMBLY_SUPPLIER_OFFER_EVIDENCE_SCOPE.into(),
                    complete: true,
                },
                commercial: ProcurementCommercialEvidence {
                    requested_boards: 10,
                    supplier: "supplier.example".into(),
                    offer_id: "offer-2026-001".into(),
                    currency: "USD".into(),
                    covered: true,
                    component_subtotal_micros: Some(1_000_000),
                    offer_valid_from_unix: 900,
                    offer_valid_until_unix: 2_000,
                    receipt_fetched_at_unix: 1_000,
                },
                policy_pack: ProcurementPolicyPackProjection {
                    source: exact_identity(&source),
                    canonical_sha256: policy_pack_sha256(pack).unwrap(),
                    id: pack.id.clone(),
                    revision: pack.revision,
                },
            },
            authorization_scope: ProcurementAuthorizationScope {
                authorization_id: "procurement-2026-001".into(),
                challenge: "c".repeat(64),
                requested_boards: 10,
                currency: "USD".into(),
                maximum_component_subtotal_micros: 1_500_000,
                valid_from_unix: 1_050,
                expires_at_unix: 1_500,
            },
            binding_sha256: String::new(),
        };
        request.binding_sha256 = request_binding_sha256(&request).unwrap();
        validate_procurement_approval_signing_request(&request).unwrap();
        request
    }

    fn rebind(request: &mut ProcurementApprovalSigningRequest) {
        request.binding_sha256 = request_binding_sha256(request).unwrap();
    }

    fn approvals(
        request: &ProcurementApprovalSigningRequest,
        pack: &OrganizationPolicyPack,
    ) -> Vec<SignedProcurementApproval> {
        vec![
            sign_procurement_approval(
                request,
                pack,
                ProcurementApprovalDecision::Approve,
                "Approved within the exact signed scope.",
                "PROC-51",
                "procurement-a",
                &[51; 32],
            )
            .unwrap(),
            sign_procurement_approval(
                request,
                pack,
                ProcurementApprovalDecision::Approve,
                "Independent approval.",
                "PROC-52",
                "procurement-b",
                &[52; 32],
            )
            .unwrap(),
        ]
    }

    #[test]
    fn freezes_request_binding_and_approval_signature_bytes() {
        let pack = policy();
        let request = sample_request(&pack);
        assert_eq!(
            request.binding_sha256,
            "0a6be51dad43100e0de1721241745f5b5f8cb45549325fe5fc96627c3a9b7012"
        );
        let signed = approvals(&request, &pack).remove(0);
        assert_eq!(
            signed.public_key,
            "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
        );
        assert_eq!(
            signed.signature,
            "8b918860afd8420978f01a3703f40d69572caadfc6b80b5be76fe9d48a48157fc42dc0d6f6e424428e50999a8bd768a86ac2b1a5ede1ba8b44405519ea24f707"
        );
    }

    #[test]
    fn verifies_sorted_dual_control_and_self_validating_assessment() {
        let pack = policy();
        let request = sample_request(&pack);
        let mut signed = approvals(&request, &pack);
        signed.reverse();
        let assessment =
            verify_procurement_cryptographic_assessment(&request, &pack, &signed, 1_200).unwrap();
        assert!(assessment.policy_satisfied);
        assert_eq!(assessment.status, "policy_satisfied");
        assert!(assessment.gate_failures.is_empty());
        assert_eq!(assessment.signed_approvals[0].signer_id, "procurement-a");
        assert_eq!(assessment.signed_approvals[1].signer_id, "procurement-b");
        assert_eq!(assessment.members[0].signer_id, "procurement-a");
        validate_procurement_cryptographic_assessment(&assessment).unwrap();

        let mut tampered = assessment;
        tampered.binding_sha256.replace_range(0..1, "0");
        assert!(validate_procurement_cryptographic_assessment(&tampered).is_err());
    }

    #[test]
    fn hard_rejects_policy_source_pin_and_closed_json_failures() {
        let pack = policy();
        let request = sample_request(&pack);
        let source = policy_source(&pack);
        parse_and_bind_procurement_policy_pack(
            &source,
            &request.evidence.policy_pack.canonical_sha256,
            &request.evidence.policy_pack,
        )
        .unwrap();

        assert!(
            parse_and_bind_procurement_policy_pack(
                &source,
                &"0".repeat(64),
                &request.evidence.policy_pack,
            )
            .is_err()
        );
        let mut wrong_projection = request.evidence.policy_pack.clone();
        wrong_projection.source.sha256 = "0".repeat(64);
        assert!(
            parse_and_bind_procurement_policy_pack(
                &source,
                &request.evidence.policy_pack.canonical_sha256,
                &wrong_projection,
            )
            .is_err()
        );

        let request_source = serde_json::to_string(&request).unwrap();
        let duplicate = request_source.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(parse_procurement_approval_signing_request(duplicate.as_bytes()).is_err());
        let mut unknown = serde_json::to_value(&request).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(
            parse_procurement_approval_signing_request(unknown.to_string().as_bytes()).is_err()
        );
    }

    #[test]
    fn signing_rejects_incomplete_approval_before_key_and_preserves_rejections() {
        let pack = policy();
        let mut request = sample_request(&pack);
        request.evidence.assembly_supplier_offer_evidence.complete = false;
        request.evidence.commercial.covered = false;
        request.evidence.commercial.component_subtotal_micros = None;
        rebind(&mut request);
        assert!(
            validate_procurement_approval_signing_inputs(
                &request,
                &pack,
                ProcurementApprovalDecision::Approve,
                "Cannot approve.",
                "PROC-51",
                "procurement-a",
            )
            .unwrap_err()
            .contains("cannot approve")
        );
        let rejected = sign_procurement_approval(
            &request,
            &pack,
            ProcurementApprovalDecision::Reject,
            "Incomplete evidence.",
            "PROC-51",
            "procurement-a",
            &[51; 32],
        )
        .unwrap();
        assert_eq!(rejected.decision, ProcurementApprovalDecision::Reject);
    }

    #[test]
    fn retains_all_frozen_policy_gate_failures_in_lexical_order() {
        let mut pack = policy();
        let policy = pack.procurement_authorization_policy.as_mut().unwrap();
        policy.maximum_validity_seconds = 300;
        policy.maximum_receipt_observation_age_seconds = 100;
        policy.maximum_component_subtotal_micros = 1_000_000;
        let mut request = sample_request(&pack);
        request.evidence.assembly_supplier_offer_evidence.complete = false;
        request.evidence.commercial.covered = false;
        request.evidence.commercial.component_subtotal_micros = None;
        request
            .authorization_scope
            .maximum_component_subtotal_micros = 1_500_000;
        rebind(&mut request);
        let signed = [
            ("procurement-a", [51; 32], "PROC-51"),
            ("procurement-b", [52; 32], "PROC-52"),
        ]
        .map(|(signer, key, ticket)| {
            sign_procurement_approval(
                &request,
                &pack,
                ProcurementApprovalDecision::Reject,
                "Not approved.",
                ticket,
                signer,
                &key,
            )
            .unwrap()
        });
        let assessment =
            verify_procurement_cryptographic_assessment(&request, &pack, &signed, 3_000).unwrap();
        let mut expected = vec![
            "approval_window_inactive".to_string(),
            "evidence_incomplete".to_string(),
            "human_rejection:count=2".to_string(),
            "insufficient_procurement_approvals:required=2:actual=0".to_string(),
            "offer_window_inactive".to_string(),
            "procurement_validity_exceeds_policy:maximum_seconds=300:actual_seconds=450"
                .to_string(),
            "receipt_observation_too_old:maximum_seconds=100:actual_seconds=2000".to_string(),
            "signed_component_subtotal_ceiling_exceeds_policy:maximum_micros=1000000:actual_micros=1500000"
                .to_string(),
            "supplier_offer_not_covered".to_string(),
        ];
        expected.sort();
        assert_eq!(assessment.gate_failures, expected);
        assert!(!assessment.policy_satisfied);
        assert_eq!(assessment.status, "not_satisfied");
    }

    #[test]
    fn retains_ceiling_and_time_gates_but_rejects_invalid_signatures_and_duplicates() {
        let pack = policy();
        let mut request = sample_request(&pack);
        request
            .authorization_scope
            .maximum_component_subtotal_micros = 900_000;
        rebind(&mut request);
        let signed = approvals(&request, &pack);
        let assessment =
            verify_procurement_cryptographic_assessment(&request, &pack, &signed, 1_200).unwrap();
        assert_eq!(
            assessment.gate_failures,
            vec![
                "component_subtotal_exceeds_signed_ceiling:maximum_micros=900000:actual_micros=1000000"
                    .to_string()
            ]
        );

        let mut tampered = signed.clone();
        tampered[0].reason.push('!');
        assert!(
            verify_procurement_cryptographic_assessment(&request, &pack, &tampered, 1_200).is_err()
        );
        let duplicate = vec![signed[0].clone(), signed[0].clone()];
        assert!(
            verify_procurement_cryptographic_assessment(&request, &pack, &duplicate, 1_200)
                .is_err()
        );
    }

    #[test]
    fn approval_signature_binds_every_fixed_envelope_context_field() {
        let pack = policy();
        let request = sample_request(&pack);
        let signed = approvals(&request, &pack).remove(0);
        let trusted_key =
            decode_hex_array::<32>(&signed.public_key, "trusted procurement public key").unwrap();

        let mut changed = signed.clone();
        changed.schema_version += 1;
        assert!(validate_signed_procurement_approval(&changed).is_err());
        assert!(verify_approval_signature(&changed, &trusted_key).is_err());

        let mut changed = signed.clone();
        changed.scope.push_str("-changed");
        assert!(validate_signed_procurement_approval(&changed).is_err());
        assert!(verify_approval_signature(&changed, &trusted_key).is_err());

        let mut changed = signed.clone();
        changed.algorithm = "ed25519-changed".into();
        assert!(validate_signed_procurement_approval(&changed).is_err());
        assert!(verify_approval_signature(&changed, &trusted_key).is_err());

        let mut changed = signed;
        changed.public_key =
            hex::encode(SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes());
        assert!(verify_approval_signature(&changed, &trusted_key).is_err());
    }

    #[test]
    fn rejects_cross_binding_window_and_timestamp_overflow() {
        let pack = policy();
        let mut request = sample_request(&pack);
        request.authorization_scope.requested_boards += 1;
        rebind(&mut request);
        assert!(validate_procurement_approval_signing_request(&request).is_err());

        let mut request = sample_request(&pack);
        request.authorization_scope.expires_at_unix =
            request.evidence.commercial.offer_valid_until_unix;
        rebind(&mut request);
        assert!(validate_procurement_approval_signing_request(&request).is_err());

        let mut request = sample_request(&pack);
        request.evidence.commercial.receipt_fetched_at_unix = MAXIMUM_TIMESTAMP + 1;
        rebind(&mut request);
        assert!(validate_procurement_approval_signing_request(&request).is_err());

        let request = sample_request(&pack);
        let signed = approvals(&request, &pack);
        assert!(
            verify_procurement_cryptographic_assessment(
                &request,
                &pack,
                &signed,
                MAXIMUM_TIMESTAMP + 1,
            )
            .is_err()
        );
    }
}
