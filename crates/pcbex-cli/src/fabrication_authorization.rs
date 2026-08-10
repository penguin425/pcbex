//! Offline, evidence-bound dual-control authorization for one fabrication scope.
//!
//! This module never contacts a factory, places an order, reserves funds, or
//! spends money.  It authenticates human signatures over evidence previously
//! reproduced by the deterministic pipeline runner.  The caller-provided
//! challenge gives each signed scope explicit replay-domain entropy, but this
//! stateless verifier cannot provide durable one-time-use enforcement; callers
//! that require it must retain and reject previously consumed challenges.

use crate::deterministic_pipeline_runner::{
    ApprovedFabricationPipelineEvidence, MAX_PLAN_BYTES, MAX_REPORT_BYTES,
    reject_duplicate_json_keys,
};
use crate::factory::{
    FactoryProvider, FactorySubmissionReceipt, factory_feedback_passed,
    validate_factory_submission_receipt, validate_manufacturing_package,
};
use crate::manufacturing_limits::MAX_PACKAGE_BYTES;
use crate::policy_pack::{
    FabricationAuthorizationPolicy, OrganizationPolicyPack, policy_pack_json_schema,
    policy_pack_sha256, validate_policy_pack,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub(crate) const SIGNED_FABRICATION_APPROVAL_SCHEMA_VERSION: u32 = 1;
pub(crate) const FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION: u32 = 1;
const SIGNATURE_DOMAIN: &str = "pcbex-fabrication-approval-v1";
const MAXIMUM_APPROVALS: usize = 100;
const MAXIMUM_VALIDITY_SECONDS: u64 = 604_800;
const MAXIMUM_QUANTITY: u32 = 1_000_000;
const MAXIMUM_TOTAL_MINOR_UNITS: u64 = 9_007_199_254_740_991;
const MAXIMUM_REASON_BYTES: usize = 4_096;
const MAXIMUM_TICKET_BYTES: usize = 256;
const MAXIMUM_FACTORY_ENDPOINT_BYTES: usize = 2_048;
pub(crate) const MAX_FACTORY_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_POLICY_PACK_BYTES: u64 = 64 * 1024 * 1024;
pub(crate) const MAX_SIGNED_FABRICATION_APPROVAL_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FabricationApprovalDecision {
    Approve,
    Reject,
}

/// The exact commercial and temporal boundary covered by every signature.
///
/// `challenge` must be caller-generated lowercase 32-byte hex.  Its presence
/// does not imply that this offline module remembers or consumes it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationAuthorizationScope {
    pub(crate) authorization_id: String,
    pub(crate) challenge: String,
    pub(crate) quantity: u32,
    pub(crate) currency: String,
    pub(crate) maximum_total_minor_units: u64,
    pub(crate) valid_from_unix: u64,
    pub(crate) expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationPipelineEvidence {
    pub(crate) plan_source: ExactArtifactIdentity,
    pub(crate) plan_sha256: String,
    pub(crate) retained_report: ExactArtifactIdentity,
    pub(crate) run_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationFactoryReceiptEvidence {
    pub(crate) receipt: ExactArtifactIdentity,
    pub(crate) provider: FactoryProvider,
    pub(crate) endpoint: String,
    pub(crate) quote_sha256: String,
    /// Always false: the existing receipt is locally normalized evidence, not
    /// a factory-signed statement, and its opaque quote is not authenticated.
    pub(crate) quote_authenticity_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationPolicyPackEvidence {
    pub(crate) source: ExactArtifactIdentity,
    pub(crate) canonical_sha256: String,
    pub(crate) id: String,
    pub(crate) revision: u32,
}

/// Complete path-free evidence shared by every approval in one authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationAuthorizationEvidence {
    pub(crate) pipeline: FabricationPipelineEvidence,
    pub(crate) manufacturing_package: ExactArtifactIdentity,
    pub(crate) factory_receipt: FabricationFactoryReceiptEvidence,
    pub(crate) policy_pack: FabricationPolicyPackEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFabricationApproval {
    pub(crate) schema_version: u32,
    pub(crate) evidence: FabricationAuthorizationEvidence,
    pub(crate) scope: FabricationAuthorizationScope,
    pub(crate) decision: FabricationApprovalDecision,
    pub(crate) reason: String,
    pub(crate) ticket: String,
    pub(crate) signer_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationAuthorizationMember {
    pub(crate) signer_id: String,
    pub(crate) public_key: String,
    pub(crate) approval_sha256: String,
    pub(crate) decision: FabricationApprovalDecision,
    pub(crate) reason: String,
    pub(crate) ticket: String,
}

/// A self-contained snapshot of one authorization verification.
///
/// Full signer-sorted signed approvals are retained so the report remains
/// cryptographically auditable.  Structurally valid rejection, insufficient
/// quorum, inactive-window, and policy-window outcomes are retained truthfully
/// as `not_authorized`; invalid signatures and mixed evidence remain errors.
/// The report itself has no outer signature or trusted timestamp and must not
/// be consumed as current authority without freshly replaying the original
/// artifacts and approvals through the CLI verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FabricationAuthorizationReport {
    pub(crate) schema_version: u32,
    pub(crate) status: String,
    pub(crate) evidence: FabricationAuthorizationEvidence,
    pub(crate) scope: FabricationAuthorizationScope,
    pub(crate) policy_pack: OrganizationPolicyPack,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) approvals: u32,
    pub(crate) rejections: u32,
    pub(crate) members: Vec<FabricationAuthorizationMember>,
    pub(crate) signed_approvals: Vec<SignedFabricationApproval>,
    pub(crate) fabrication_authorized: bool,
    pub(crate) gate_failures: Vec<String>,
    /// Always false.  Durable replay prevention requires external retained
    /// state that this offline verification artifact deliberately lacks.
    pub(crate) challenge_one_time_use_enforced: bool,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    evidence: &'a FabricationAuthorizationEvidence,
    scope: &'a FabricationAuthorizationScope,
    decision: FabricationApprovalDecision,
    reason: &'a str,
    ticket: &'a str,
    signer_id: &'a str,
}

/// Capture and independently validate the three raw artifacts selected by a
/// freshly replayed, approved deterministic pipeline.
///
/// This is deliberately byte-oriented and path-free.  Besides matching every
/// expected identity, it revalidates the manufacturing ZIP, duplicate-free
/// closed receipt, passing receipt/package binding, duplicate-free policy
/// pack, policy semantics, and required fabrication trust policy.
pub(crate) fn capture_fabrication_authorization_evidence(
    replay: &ApprovedFabricationPipelineEvidence,
    manufacturing_package: &[u8],
    factory_receipt: &[u8],
    policy_pack_source: &[u8],
) -> Result<(FabricationAuthorizationEvidence, OrganizationPolicyPack), String> {
    validate_replay_seed(replay)?;
    let package_identity = exact_identity(manufacturing_package);
    let receipt_identity = exact_identity(factory_receipt);
    let policy_identity = exact_identity(policy_pack_source);
    if package_identity != replay.manufacturing_package {
        return Err(
            "manufacturing package bytes do not match the freshly replayed pipeline evidence"
                .into(),
        );
    }
    if receipt_identity != replay.factory_receipt {
        return Err(
            "factory receipt bytes do not match the freshly replayed pipeline evidence".into(),
        );
    }
    if policy_identity != replay.policy_pack {
        return Err("policy pack bytes do not match the freshly replayed pipeline evidence".into());
    }
    validate_artifact_identity(
        &package_identity,
        MAX_PACKAGE_BYTES,
        "manufacturing package",
    )?;
    validate_artifact_identity(
        &receipt_identity,
        MAX_FACTORY_RECEIPT_BYTES,
        "factory receipt",
    )?;
    validate_artifact_identity(
        &policy_identity,
        MAX_POLICY_PACK_BYTES,
        "policy pack source",
    )?;

    reject_duplicate_json_keys(factory_receipt)
        .map_err(|error| format!("invalid factory receipt JSON: {error:#}"))?;
    let receipt: FactorySubmissionReceipt = serde_json::from_slice(factory_receipt)
        .map_err(|error| format!("invalid factory receipt JSON: {error}"))?;
    validate_factory_submission_receipt(&receipt, false)
        .map_err(|error| format!("invalid factory receipt: {error}"))?;

    reject_duplicate_json_keys(policy_pack_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error:#}"))?;
    let policy_pack: OrganizationPolicyPack = serde_json::from_slice(policy_pack_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error}"))?;
    validate_policy_pack(&policy_pack)?;
    if policy_pack.fabrication_authorization_policy.is_none() {
        return Err("organization policy pack has no fabrication authorization policy".into());
    }

    validate_manufacturing_package(manufacturing_package)
        .map_err(|error| format!("invalid manufacturing package: {error}"))?;
    if receipt.package_bytes != package_identity.bytes
        || receipt.package_sha256 != package_identity.sha256
        || receipt.request_sha256 != package_identity.sha256
    {
        return Err(
            "factory receipt does not identify the exact validated manufacturing package".into(),
        );
    }
    if !factory_feedback_passed(&receipt) {
        return Err(
            "factory receipt did not pass accepted, DFM, HTTP, and fail-closed severity policy"
                .into(),
        );
    }
    let quote = receipt
        .quote
        .as_ref()
        .ok_or_else(|| "factory receipt has no quote to bind".to_string())?;
    if !quote.is_object() {
        return Err("factory receipt quote must be an opaque JSON object".into());
    }

    let evidence = FabricationAuthorizationEvidence {
        pipeline: FabricationPipelineEvidence {
            plan_source: replay.plan_source.clone(),
            plan_sha256: replay.plan_sha256.clone(),
            retained_report: replay.report.clone(),
            run_sha256: replay.run_sha256.clone(),
        },
        manufacturing_package: package_identity,
        factory_receipt: FabricationFactoryReceiptEvidence {
            receipt: receipt_identity,
            provider: receipt.provider,
            endpoint: receipt.endpoint,
            quote_sha256: canonical_json_sha256(quote, "factory quote")?,
            quote_authenticity_verified: false,
        },
        policy_pack: FabricationPolicyPackEvidence {
            source: policy_identity,
            canonical_sha256: policy_pack_sha256(&policy_pack)?,
            id: policy_pack.id.clone(),
            revision: policy_pack.revision,
        },
    };
    validate_fabrication_authorization_evidence(&evidence)?;
    Ok((evidence, policy_pack))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sign_fabrication_approval(
    evidence: &FabricationAuthorizationEvidence,
    policy_pack: &OrganizationPolicyPack,
    scope: &FabricationAuthorizationScope,
    decision: FabricationApprovalDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedFabricationApproval, String> {
    validate_fabrication_approval_signing_inputs(
        evidence,
        policy_pack,
        scope,
        decision,
        reason,
        ticket,
        signer_id,
    )?;
    let trusted = trusted_fabrication_signer(policy_pack, signer_id)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if public_key != trusted.public_key {
        return Err(
            "fabrication approval private key does not match the signer's trusted key".into(),
        );
    }
    let payload = signature_payload(evidence, scope, decision, reason, ticket, signer_id)?;
    let signed = SignedFabricationApproval {
        schema_version: SIGNED_FABRICATION_APPROVAL_SCHEMA_VERSION,
        evidence: evidence.clone(),
        scope: scope.clone(),
        decision,
        reason: reason.into(),
        ticket: ticket.into(),
        signer_id: signer_id.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: hex::encode(signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_fabrication_approval(&signed)?;
    Ok(signed)
}

/// Validate every public signing input, including dedicated signer trust,
/// before a caller reads private-key material.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_fabrication_approval_signing_inputs(
    evidence: &FabricationAuthorizationEvidence,
    policy_pack: &OrganizationPolicyPack,
    scope: &FabricationAuthorizationScope,
    _decision: FabricationApprovalDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<(), String> {
    validate_fabrication_authorization_evidence(evidence)?;
    validate_policy_pack_binding(evidence, policy_pack)?;
    validate_fabrication_authorization_scope(scope)?;
    validate_text(reason, MAXIMUM_REASON_BYTES, "fabrication approval reason")?;
    validate_text(ticket, MAXIMUM_TICKET_BYTES, "fabrication approval ticket")?;
    validate_slug("fabrication approval signer", signer_id)?;
    trusted_fabrication_signer(policy_pack, signer_id).map(|_| ())
}

fn trusted_fabrication_signer<'a>(
    policy_pack: &'a OrganizationPolicyPack,
    signer_id: &str,
) -> Result<&'a crate::policy_pack::TrustedApprovalKey, String> {
    policy_pack
        .fabrication_authorization_policy
        .as_ref()
        .expect("validated fabrication policy is present")
        .trusted_keys
        .iter()
        .find(|trusted| trusted.signer_id == signer_id)
        .ok_or_else(|| {
            format!("fabrication signer {signer_id:?} is not trusted by the organization policy")
        })
}

fn validate_policy_pack_binding(
    evidence: &FabricationAuthorizationEvidence,
    policy_pack: &OrganizationPolicyPack,
) -> Result<(), String> {
    validate_policy_pack(policy_pack)?;
    let policy = policy_pack
        .fabrication_authorization_policy
        .as_ref()
        .ok_or_else(|| {
            "organization policy pack has no fabrication authorization policy".to_string()
        })?;
    validate_fabrication_policy(policy)?;
    if evidence.policy_pack.id != policy_pack.id
        || evidence.policy_pack.revision != policy_pack.revision
        || evidence.policy_pack.canonical_sha256 != policy_pack_sha256(policy_pack)?
    {
        return Err(
            "fabrication evidence does not bind the supplied organization policy pack".into(),
        );
    }
    Ok(())
}

/// Verify a structurally valid, policy-trusted decision set at the caller's
/// current time and retain its truthful gate outcome.
///
/// Successful return authorizes only the signed maximum, quantity, currency,
/// window, evidence, and authorization/challenge identifiers.  It performs no
/// network, order, reservation, or spend action.
pub(crate) fn verify_fabrication_authorization(
    evidence: &FabricationAuthorizationEvidence,
    policy_pack: &OrganizationPolicyPack,
    signed_approvals: &[SignedFabricationApproval],
    evaluated_at_unix: u64,
) -> Result<FabricationAuthorizationReport, String> {
    validate_fabrication_authorization_evidence(evidence)?;
    validate_policy_pack_binding(evidence, policy_pack)?;
    let policy = policy_pack
        .fabrication_authorization_policy
        .as_ref()
        .expect("validated policy binding has a fabrication policy");
    if signed_approvals.is_empty() || signed_approvals.len() > MAXIMUM_APPROVALS {
        return Err(format!(
            "fabrication approval set must contain 1 to {MAXIMUM_APPROVALS} entries"
        ));
    }

    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut common_scope: Option<FabricationAuthorizationScope> = None;
    let mut retained = Vec::with_capacity(signed_approvals.len());
    for signed in signed_approvals {
        validate_signed_fabrication_approval(signed)?;
        if &signed.evidence != evidence {
            return Err("fabrication approvals do not bind the exact common evidence".into());
        }
        if common_scope
            .as_ref()
            .is_some_and(|scope| scope != &signed.scope)
        {
            return Err("fabrication approvals do not bind the exact common scope".into());
        }
        common_scope.get_or_insert_with(|| signed.scope.clone());
        let trusted = policy
            .trusted_keys
            .iter()
            .find(|trusted| trusted.signer_id == signed.signer_id)
            .ok_or_else(|| {
                format!(
                    "fabrication signer {:?} is not trusted by the organization policy",
                    signed.signer_id
                )
            })?;
        verify_approval_signature(
            signed,
            &decode_hex_array::<32>(&trusted.public_key, "trusted fabrication key")?,
        )?;
        if !signer_ids.insert(signed.signer_id.as_str())
            || !public_keys.insert(signed.public_key.as_str())
        {
            return Err(
                "fabrication approvals require distinct trusted signer IDs and keys".into(),
            );
        }
        retained.push(signed.clone());
    }
    let scope = common_scope.expect("a non-empty approval set has a scope");
    let duration = validate_fabrication_authorization_scope(&scope)?;
    let approvals = retained
        .iter()
        .filter(|signed| signed.decision == FabricationApprovalDecision::Approve)
        .count() as u32;
    let rejections = retained.len() as u32 - approvals;
    let gate_failures = fabrication_gate_failures(
        &scope,
        duration,
        policy,
        approvals,
        rejections,
        evaluated_at_unix,
    );
    let fabrication_authorized = gate_failures.is_empty();

    retained.sort_by(|left, right| left.signer_id.cmp(&right.signer_id));
    let members = retained
        .iter()
        .map(fabrication_member)
        .collect::<Result<Vec<_>, _>>()?;
    let report = FabricationAuthorizationReport {
        schema_version: FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION,
        status: if fabrication_authorized {
            "fabrication_authorized"
        } else {
            "not_authorized"
        }
        .into(),
        evidence: evidence.clone(),
        scope,
        policy_pack: policy_pack.clone(),
        evaluated_at_unix,
        approvals,
        rejections,
        members,
        signed_approvals: retained,
        fabrication_authorized,
        gate_failures,
        challenge_one_time_use_enforced: false,
    };
    validate_fabrication_authorization_report(&report)?;
    Ok(report)
}

pub(crate) fn parse_signed_fabrication_approval(
    source: &str,
) -> Result<SignedFabricationApproval, String> {
    if source.len() as u64 > MAX_SIGNED_FABRICATION_APPROVAL_BYTES {
        return Err(format!(
            "signed fabrication approval exceeds {MAX_SIGNED_FABRICATION_APPROVAL_BYTES} bytes"
        ));
    }
    reject_duplicate_json_keys(source.as_bytes())
        .map_err(|error| format!("invalid signed fabrication approval JSON: {error:#}"))?;
    let signed: SignedFabricationApproval = serde_json::from_str(source)
        .map_err(|error| format!("invalid signed fabrication approval JSON: {error}"))?;
    validate_signed_fabrication_approval(&signed)?;
    Ok(signed)
}

pub(crate) fn validate_signed_fabrication_approval(
    signed: &SignedFabricationApproval,
) -> Result<(), String> {
    if signed.schema_version != SIGNED_FABRICATION_APPROVAL_SCHEMA_VERSION {
        return Err(format!(
            "unsupported signed fabrication approval schema_version {}; expected {}",
            signed.schema_version, SIGNED_FABRICATION_APPROVAL_SCHEMA_VERSION
        ));
    }
    if signed.algorithm != "ed25519" {
        return Err(format!(
            "unsupported fabrication approval signature algorithm {:?}",
            signed.algorithm
        ));
    }
    validate_fabrication_authorization_evidence(&signed.evidence)?;
    validate_fabrication_authorization_scope(&signed.scope)?;
    validate_text(
        &signed.reason,
        MAXIMUM_REASON_BYTES,
        "fabrication approval reason",
    )?;
    validate_text(
        &signed.ticket,
        MAXIMUM_TICKET_BYTES,
        "fabrication approval ticket",
    )?;
    validate_slug("fabrication approval signer", &signed.signer_id)?;
    decode_hex_array::<32>(&signed.public_key, "fabrication approval public key")?;
    decode_hex_array::<64>(&signed.signature, "fabrication approval signature")?;
    Ok(())
}

fn validate_fabrication_authorization_report(
    report: &FabricationAuthorizationReport,
) -> Result<(), String> {
    if report.schema_version != FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION
        || !matches!(
            report.status.as_str(),
            "fabrication_authorized" | "not_authorized"
        )
        || report.challenge_one_time_use_enforced
    {
        return Err("fabrication authorization report governance boundary is invalid".into());
    }
    validate_fabrication_authorization_evidence(&report.evidence)?;
    let duration = validate_fabrication_authorization_scope(&report.scope)?;
    validate_policy_pack_binding(&report.evidence, &report.policy_pack)?;
    let policy = report
        .policy_pack
        .fabrication_authorization_policy
        .as_ref()
        .expect("validated policy binding has a fabrication policy");
    if report.signed_approvals.is_empty()
        || report.signed_approvals.len() > MAXIMUM_APPROVALS
        || report.approvals.checked_add(report.rejections)
            != Some(report.signed_approvals.len() as u32)
        || report.members.len() != report.signed_approvals.len()
    {
        return Err("fabrication authorization policy, time, or counts are invalid".into());
    }

    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    let mut previous_signer: Option<&str> = None;
    let mut expected_members = Vec::with_capacity(report.signed_approvals.len());
    let mut approvals = 0_u32;
    for signed in &report.signed_approvals {
        validate_signed_fabrication_approval(signed)?;
        if signed.evidence != report.evidence
            || signed.scope != report.scope
            || previous_signer.is_some_and(|previous| previous >= signed.signer_id.as_str())
        {
            return Err(
                "fabrication authorization signed approvals are inconsistent or unordered".into(),
            );
        }
        let trusted = report
            .policy_pack
            .fabrication_authorization_policy
            .as_ref()
            .expect("validated fabrication policy is present")
            .trusted_keys
            .iter()
            .find(|trusted| trusted.signer_id == signed.signer_id)
            .ok_or_else(|| {
                format!(
                    "fabrication report signer {:?} is not present in its retained policy",
                    signed.signer_id
                )
            })?;
        verify_approval_signature(
            signed,
            &decode_hex_array::<32>(&trusted.public_key, "retained trusted fabrication key")?,
        )?;
        if !signer_ids.insert(signed.signer_id.as_str())
            || !public_keys.insert(signed.public_key.as_str())
        {
            return Err("fabrication authorization signatures are not independent".into());
        }
        previous_signer = Some(signed.signer_id.as_str());
        approvals += u32::from(signed.decision == FabricationApprovalDecision::Approve);
        expected_members.push(fabrication_member(signed)?);
    }
    let rejections = report.signed_approvals.len() as u32 - approvals;
    let expected_failures = fabrication_gate_failures(
        &report.scope,
        duration,
        policy,
        approvals,
        rejections,
        report.evaluated_at_unix,
    );
    let expected_authorized = expected_failures.is_empty();
    if report.members != expected_members
        || report.approvals != approvals
        || report.rejections != rejections
        || report.gate_failures != expected_failures
        || report.fabrication_authorized != expected_authorized
        || report.status
            != if expected_authorized {
                "fabrication_authorized"
            } else {
                "not_authorized"
            }
    {
        return Err("fabrication authorization members do not match retained signatures".into());
    }
    Ok(())
}

fn validate_fabrication_authorization_evidence(
    evidence: &FabricationAuthorizationEvidence,
) -> Result<(), String> {
    validate_artifact_identity(
        &evidence.pipeline.plan_source,
        MAX_PLAN_BYTES,
        "deterministic pipeline plan source",
    )?;
    validate_digest(
        &evidence.pipeline.plan_sha256,
        "deterministic pipeline plan SHA-256",
    )?;
    validate_artifact_identity(
        &evidence.pipeline.retained_report,
        MAX_REPORT_BYTES as u64 + 1,
        "retained deterministic pipeline report",
    )?;
    validate_digest(
        &evidence.pipeline.run_sha256,
        "deterministic pipeline run SHA-256",
    )?;
    validate_artifact_identity(
        &evidence.manufacturing_package,
        MAX_PACKAGE_BYTES,
        "manufacturing package",
    )?;
    validate_artifact_identity(
        &evidence.factory_receipt.receipt,
        MAX_FACTORY_RECEIPT_BYTES,
        "factory receipt",
    )?;
    validate_endpoint_evidence(&evidence.factory_receipt.endpoint)?;
    validate_digest(
        &evidence.factory_receipt.quote_sha256,
        "canonical factory quote SHA-256",
    )?;
    if evidence.factory_receipt.quote_authenticity_verified {
        return Err(
            "factory quote authenticity cannot be claimed from the unsigned normalized receipt"
                .into(),
        );
    }
    validate_artifact_identity(
        &evidence.policy_pack.source,
        MAX_POLICY_PACK_BYTES,
        "policy pack source",
    )?;
    validate_digest(
        &evidence.policy_pack.canonical_sha256,
        "canonical policy pack SHA-256",
    )?;
    validate_slug("fabrication policy pack id", &evidence.policy_pack.id)?;
    if evidence.policy_pack.revision == 0 {
        return Err("fabrication policy pack revision must be greater than zero".into());
    }
    Ok(())
}

fn validate_replay_seed(replay: &ApprovedFabricationPipelineEvidence) -> Result<(), String> {
    validate_artifact_identity(
        &replay.plan_source,
        MAX_PLAN_BYTES,
        "replayed deterministic pipeline plan source",
    )?;
    validate_digest(
        &replay.plan_sha256,
        "replayed deterministic pipeline plan SHA-256",
    )?;
    validate_artifact_identity(
        &replay.report,
        MAX_REPORT_BYTES as u64 + 1,
        "replayed deterministic pipeline report",
    )?;
    validate_digest(
        &replay.run_sha256,
        "replayed deterministic pipeline run SHA-256",
    )?;
    validate_artifact_identity(
        &replay.manufacturing_package,
        MAX_PACKAGE_BYTES,
        "replayed manufacturing package",
    )?;
    validate_artifact_identity(
        &replay.factory_receipt,
        MAX_FACTORY_RECEIPT_BYTES,
        "replayed factory receipt",
    )?;
    validate_artifact_identity(
        &replay.policy_pack,
        MAX_POLICY_PACK_BYTES,
        "replayed policy pack",
    )
}

fn validate_fabrication_authorization_scope(
    scope: &FabricationAuthorizationScope,
) -> Result<u64, String> {
    validate_slug("fabrication authorization id", &scope.authorization_id)?;
    validate_digest(&scope.challenge, "fabrication authorization challenge")?;
    if scope.quantity == 0 || scope.quantity > MAXIMUM_QUANTITY {
        return Err(format!(
            "fabrication quantity must be between 1 and {MAXIMUM_QUANTITY}"
        ));
    }
    if scope.currency.len() != 3 || !scope.currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(
            "fabrication currency must contain exactly three uppercase ASCII letters".into(),
        );
    }
    if scope.maximum_total_minor_units == 0
        || scope.maximum_total_minor_units > MAXIMUM_TOTAL_MINOR_UNITS
    {
        return Err(format!(
            "fabrication maximum total must be between 1 and {MAXIMUM_TOTAL_MINOR_UNITS} minor units"
        ));
    }
    let duration = scope
        .expires_at_unix
        .checked_sub(scope.valid_from_unix)
        .ok_or_else(|| "fabrication authorization expiry precedes validity".to_string())?;
    if duration == 0 || duration > MAXIMUM_VALIDITY_SECONDS {
        return Err(format!(
            "fabrication authorization window must be 1 to {MAXIMUM_VALIDITY_SECONDS} seconds"
        ));
    }
    Ok(duration)
}

fn validate_fabrication_policy(policy: &FabricationAuthorizationPolicy) -> Result<(), String> {
    if !(2..=MAXIMUM_APPROVALS as u32).contains(&policy.minimum_approvals)
        || !(1..=MAXIMUM_VALIDITY_SECONDS).contains(&policy.maximum_validity_seconds)
        || !(2..=MAXIMUM_APPROVALS).contains(&policy.trusted_keys.len())
        || policy.minimum_approvals as usize > policy.trusted_keys.len()
    {
        return Err(
            "retained fabrication authorization policy is outside its closed bounds".into(),
        );
    }
    let mut signer_ids = HashSet::new();
    let mut public_keys = HashSet::new();
    for trusted in &policy.trusted_keys {
        validate_slug("trusted fabrication signer", &trusted.signer_id)?;
        decode_hex_array::<32>(&trusted.public_key, "trusted fabrication public key")?;
        if !signer_ids.insert(trusted.signer_id.as_str())
            || !public_keys.insert(trusted.public_key.as_str())
        {
            return Err(
                "retained fabrication authorization policy has duplicate signers or keys".into(),
            );
        }
    }
    Ok(())
}

fn fabrication_gate_failures(
    scope: &FabricationAuthorizationScope,
    duration: u64,
    policy: &FabricationAuthorizationPolicy,
    approvals: u32,
    rejections: u32,
    evaluated_at_unix: u64,
) -> Vec<String> {
    let mut failures = Vec::new();
    if duration > policy.maximum_validity_seconds {
        failures.push(format!(
            "fabrication_validity_exceeds_policy:maximum_seconds={}:actual_seconds={duration}",
            policy.maximum_validity_seconds,
        ));
    }
    if evaluated_at_unix < scope.valid_from_unix || evaluated_at_unix > scope.expires_at_unix {
        failures.push("approval_window_inactive".into());
    }
    if approvals < policy.minimum_approvals {
        failures.push(format!(
            "insufficient_fabrication_approvals:required={}:actual={approvals}",
            policy.minimum_approvals
        ));
    }
    if rejections > 0 {
        failures.push(format!("human_rejection:count={rejections}"));
    }
    failures.sort();
    failures
}

fn verify_approval_signature(
    signed: &SignedFabricationApproval,
    trusted_public_key: &[u8; 32],
) -> Result<(), String> {
    let public_key = decode_hex_array::<32>(&signed.public_key, "fabrication approval public key")?;
    if &public_key != trusted_public_key {
        return Err("fabrication approval public key does not match its trusted key".into());
    }
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid fabrication approval public key: {error}"))?;
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &signed.signature,
        "fabrication approval signature",
    )?);
    let payload = signature_payload(
        &signed.evidence,
        &signed.scope,
        signed.decision,
        &signed.reason,
        &signed.ticket,
        &signed.signer_id,
    )?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid fabrication approval signature: {error}"))
}

fn signature_payload(
    evidence: &FabricationAuthorizationEvidence,
    scope: &FabricationAuthorizationScope,
    decision: FabricationApprovalDecision,
    reason: &str,
    ticket: &str,
    signer_id: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        evidence,
        scope,
        decision,
        reason,
        ticket,
        signer_id,
    })
    .map_err(|error| format!("serializing fabrication approval signature payload: {error}"))
}

fn fabrication_member(
    signed: &SignedFabricationApproval,
) -> Result<FabricationAuthorizationMember, String> {
    Ok(FabricationAuthorizationMember {
        signer_id: signed.signer_id.clone(),
        public_key: signed.public_key.clone(),
        approval_sha256: canonical_json_sha256(signed, "signed fabrication approval")?,
        decision: signed.decision,
        reason: signed.reason.clone(),
        ticket: signed.ticket.clone(),
    })
}

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing canonical {label}: {error}"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
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

fn validate_endpoint_evidence(endpoint: &str) -> Result<(), String> {
    if endpoint.is_empty()
        || endpoint.len() > MAXIMUM_FACTORY_ENDPOINT_BYTES
        || endpoint
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || endpoint.contains('?')
        || endpoint.contains('#')
    {
        return Err("factory endpoint evidence is not a bounded HTTPS endpoint".into());
    }
    let remainder = endpoint
        .strip_prefix("https://")
        .ok_or_else(|| "factory endpoint evidence must use HTTPS".to_string())?;
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("factory endpoint evidence has an invalid authority".into());
    }
    Ok(())
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

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > maximum || value.contains('\0') {
        return Err(format!("{label} must contain 1 to {maximum} bytes"));
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

pub(crate) fn signed_fabrication_approval_json_schema() -> Value {
    let mut schema = signed_approval_schema_body();
    let object = schema
        .as_object_mut()
        .expect("signed fabrication approval schema is an object");
    object.insert(
        "$schema".into(),
        json!("https://json-schema.org/draft/2020-12/schema"),
    );
    object.insert(
        "$id".into(),
        json!("https://github.com/penguin425/pcbex/schema/signed-fabrication-approval-v1.json"),
    );
    object.insert("title".into(), json!("pcbex signed fabrication approval"));
    schema
}

pub(crate) fn fabrication_authorization_report_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/fabrication-authorization-report-v1.json",
        "title": "pcbex offline fabrication authorization report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "status", "evidence", "scope", "policy_pack",
            "evaluated_at_unix", "approvals", "rejections", "members",
            "signed_approvals", "fabrication_authorized",
            "gate_failures", "challenge_one_time_use_enforced"
        ],
        "properties": {
            "schema_version": {"const": FABRICATION_AUTHORIZATION_REPORT_SCHEMA_VERSION},
            "status": {"enum": ["fabrication_authorized", "not_authorized"]},
            "evidence": evidence_schema(),
            "scope": scope_schema(),
            "policy_pack": {
                "allOf": [
                    policy_pack_json_schema(),
                    {"required": ["fabrication_authorization_policy"]}
                ]
            },
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "approvals": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_APPROVALS},
            "rejections": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_APPROVALS},
            "members": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_APPROVALS,
                "items": member_schema()
            },
            "signed_approvals": {
                "type": "array", "minItems": 1, "maxItems": MAXIMUM_APPROVALS,
                "items": signed_approval_schema_body()
            },
            "fabrication_authorized": {"type": "boolean"},
            "gate_failures": {
                "type": "array", "maxItems": 4,
                "items": {"type": "string", "minLength": 1, "maxLength": 256}
            },
            "challenge_one_time_use_enforced": {"const": false}
        },
        "allOf": [{
            "if": {
                "properties": {"fabrication_authorized": {"const": true}},
                "required": ["fabrication_authorized"]
            },
            "then": {
                "properties": {
                    "status": {"const": "fabrication_authorized"},
                    "rejections": {"const": 0},
                    "gate_failures": {"maxItems": 0}
                }
            },
            "else": {
                "properties": {
                    "status": {"const": "not_authorized"},
                    "gate_failures": {"minItems": 1}
                }
            }
        }]
    })
}

fn signed_approval_schema_body() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "evidence", "scope", "decision", "reason",
            "ticket", "signer_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_FABRICATION_APPROVAL_SCHEMA_VERSION},
            "evidence": evidence_schema(),
            "scope": scope_schema(),
            "decision": {"enum": ["approve", "reject"]},
            "reason": text_schema(MAXIMUM_REASON_BYTES),
            "ticket": text_schema(MAXIMUM_TICKET_BYTES),
            "signer_id": slug_schema(),
            "algorithm": {"const": "ed25519"},
            "public_key": digest_schema(),
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

fn evidence_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "pipeline", "manufacturing_package", "factory_receipt", "policy_pack"
        ],
        "properties": {
            "pipeline": {
                "type": "object", "additionalProperties": false,
                "required": ["plan_source", "plan_sha256", "retained_report", "run_sha256"],
                "properties": {
                    "plan_source": exact_identity_schema(MAX_PLAN_BYTES),
                    "plan_sha256": digest_schema(),
                    "retained_report": exact_identity_schema(MAX_REPORT_BYTES as u64 + 1),
                    "run_sha256": digest_schema()
                }
            },
            "manufacturing_package": exact_identity_schema(MAX_PACKAGE_BYTES),
            "factory_receipt": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "receipt", "provider", "endpoint", "quote_sha256",
                    "quote_authenticity_verified"
                ],
                "properties": {
                    "receipt": exact_identity_schema(MAX_FACTORY_RECEIPT_BYTES),
                    "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
                    "endpoint": {
                        "type": "string", "minLength": 1,
                        "maxLength": MAXIMUM_FACTORY_ENDPOINT_BYTES,
                        "pattern": "^https://[^/?#@]+(?:/[^?#]*)?$"
                    },
                    "quote_sha256": digest_schema(),
                    "quote_authenticity_verified": {"const": false}
                }
            },
            "policy_pack": {
                "type": "object", "additionalProperties": false,
                "required": ["source", "canonical_sha256", "id", "revision"],
                "properties": {
                    "source": exact_identity_schema(MAX_POLICY_PACK_BYTES),
                    "canonical_sha256": digest_schema(),
                    "id": slug_schema(),
                    "revision": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64}
                }
            }
        }
    })
}

fn scope_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "authorization_id", "challenge", "quantity", "currency",
            "maximum_total_minor_units", "valid_from_unix", "expires_at_unix"
        ],
        "properties": {
            "authorization_id": slug_schema(),
            "challenge": digest_schema(),
            "quantity": {"type": "integer", "minimum": 1, "maximum": MAXIMUM_QUANTITY},
            "currency": {"type": "string", "pattern": "^[A-Z]{3}$"},
            "maximum_total_minor_units": {
                "type": "integer", "minimum": 1, "maximum": MAXIMUM_TOTAL_MINOR_UNITS
            },
            "valid_from_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1}
        }
    })
}

fn member_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "signer_id", "public_key", "approval_sha256", "decision", "reason", "ticket"
        ],
        "properties": {
            "signer_id": slug_schema(),
            "public_key": digest_schema(),
            "approval_sha256": digest_schema(),
            "decision": {"enum": ["approve", "reject"]},
            "reason": text_schema(MAXIMUM_REASON_BYTES),
            "ticket": text_schema(MAXIMUM_TICKET_BYTES)
        }
    })
}

fn exact_identity_schema(maximum_bytes: u64) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1, "maximum": maximum_bytes},
            "sha256": digest_schema()
        }
    })
}

fn slug_schema() -> Value {
    json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"})
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn text_schema(maximum_bytes: usize) -> Value {
    json!({"type": "string", "minLength": 1, "maxLength": maximum_bytes})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_pack::{TrustedApprovalKey, parse_policy_pack};

    fn identity(seed: char, bytes: u64) -> ExactArtifactIdentity {
        ExactArtifactIdentity {
            bytes,
            sha256: seed.to_string().repeat(64),
        }
    }

    fn sample_evidence(pack: &OrganizationPolicyPack) -> FabricationAuthorizationEvidence {
        FabricationAuthorizationEvidence {
            pipeline: FabricationPipelineEvidence {
                plan_source: identity('1', 100),
                plan_sha256: "2".repeat(64),
                retained_report: identity('3', 200),
                run_sha256: "4".repeat(64),
            },
            manufacturing_package: identity('5', 300),
            factory_receipt: FabricationFactoryReceiptEvidence {
                receipt: identity('6', 400),
                provider: FactoryProvider::Generic,
                endpoint: "https://factory.example/quote".into(),
                quote_sha256: "7".repeat(64),
                quote_authenticity_verified: false,
            },
            policy_pack: FabricationPolicyPackEvidence {
                source: identity('8', 500),
                canonical_sha256: policy_pack_sha256(pack).unwrap(),
                id: pack.id.clone(),
                revision: pack.revision,
            },
        }
    }

    fn scope() -> FabricationAuthorizationScope {
        FabricationAuthorizationScope {
            authorization_id: "fab-2026-001".into(),
            challenge: "9".repeat(64),
            quantity: 25,
            currency: "USD".into(),
            maximum_total_minor_units: 125_000,
            valid_from_unix: 1_000,
            expires_at_unix: 1_600,
        }
    }

    fn policy() -> OrganizationPolicyPack {
        let mut pack =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        pack.fabrication_authorization_policy = Some(FabricationAuthorizationPolicy {
            minimum_approvals: 2,
            maximum_validity_seconds: 3_600,
            trusted_keys: vec![
                TrustedApprovalKey {
                    signer_id: "fabrication-a".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes(),
                    ),
                },
                TrustedApprovalKey {
                    signer_id: "fabrication-b".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&[42; 32]).verifying_key().to_bytes(),
                    ),
                },
            ],
        });
        validate_policy_pack(&pack).unwrap();
        pack
    }

    fn approvals(
        evidence: &FabricationAuthorizationEvidence,
        policy_pack: &OrganizationPolicyPack,
        scope: &FabricationAuthorizationScope,
    ) -> Vec<SignedFabricationApproval> {
        vec![
            sign_fabrication_approval(
                evidence,
                policy_pack,
                scope,
                FabricationApprovalDecision::Approve,
                "Approved within the signed maximum.",
                "FAB-41",
                "fabrication-a",
                &[41; 32],
            )
            .unwrap(),
            sign_fabrication_approval(
                evidence,
                policy_pack,
                scope,
                FabricationApprovalDecision::Approve,
                "Independent approval.",
                "FAB-42",
                "fabrication-b",
                &[42; 32],
            )
            .unwrap(),
        ]
    }

    #[test]
    fn verifies_dual_control_and_retains_full_sorted_signatures() {
        let pack = policy();
        let evidence = sample_evidence(&pack);
        let scope = scope();
        let mut signed = approvals(&evidence, &pack, &scope);
        signed.reverse();
        let report = verify_fabrication_authorization(&evidence, &pack, &signed, 1_200).unwrap();
        assert!(report.fabrication_authorized);
        assert!(!report.challenge_one_time_use_enforced);
        assert!(!report.evidence.factory_receipt.quote_authenticity_verified);
        assert_eq!(report.signed_approvals.len(), 2);
        assert_eq!(report.signed_approvals[0].signer_id, "fabrication-a");
        assert_eq!(report.signed_approvals[1].signer_id, "fabrication-b");
        assert!(
            report
                .signed_approvals
                .iter()
                .all(|approval| approval.signature.len() == 128)
        );

        let one_approval = vec![signed[0].clone()];
        let insufficient =
            verify_fabrication_authorization(&evidence, &pack, &one_approval, 1_200).unwrap();
        assert!(!insufficient.fabrication_authorized);
        assert_eq!(insufficient.approvals, 1);
        assert_eq!(insufficient.rejections, 0);
        assert_eq!(
            insufficient.gate_failures,
            vec!["insufficient_fabrication_approvals:required=2:actual=1".to_string()]
        );
    }

    #[test]
    fn retains_rejection_and_expiry_but_rejects_mixed_or_tampered_approvals() {
        let pack = policy();
        let evidence = sample_evidence(&pack);
        let scope = scope();
        let mut signed = approvals(&evidence, &pack, &scope);

        let rejected = sign_fabrication_approval(
            &evidence,
            &pack,
            &scope,
            FabricationApprovalDecision::Reject,
            "Do not fabricate.",
            "FAB-42",
            "fabrication-b",
            &[42; 32],
        )
        .unwrap();
        signed[1] = rejected;
        let rejected_report =
            verify_fabrication_authorization(&evidence, &pack, &signed, 1_200).unwrap();
        assert!(!rejected_report.fabrication_authorized);
        assert_eq!(rejected_report.status, "not_authorized");
        assert_eq!(rejected_report.approvals, 1);
        assert_eq!(rejected_report.rejections, 1);
        assert!(
            rejected_report
                .gate_failures
                .contains(&"human_rejection:count=1".into())
        );
        validate_fabrication_authorization_report(&rejected_report).unwrap();

        let mut signed = approvals(&evidence, &pack, &scope);
        signed[1].scope.quantity += 1;
        assert!(verify_fabrication_authorization(&evidence, &pack, &signed, 1_200).is_err());

        let signed = approvals(&evidence, &pack, &scope);
        let expired = verify_fabrication_authorization(&evidence, &pack, &signed, 1_601).unwrap();
        assert!(!expired.fabrication_authorized);
        assert_eq!(
            expired.gate_failures,
            vec!["approval_window_inactive".to_string()]
        );

        let mut signed = approvals(&evidence, &pack, &scope);
        signed[0].reason.push('!');
        assert!(verify_fabrication_authorization(&evidence, &pack, &signed, 1_200).is_err());
    }

    #[test]
    fn rejects_duplicate_signer_and_retains_policy_window_overrun() {
        let pack = policy();
        let evidence = sample_evidence(&pack);
        let scope = scope();
        let mut signed = approvals(&evidence, &pack, &scope);
        signed[1] = signed[0].clone();
        assert!(verify_fabrication_authorization(&evidence, &pack, &signed, 1_200).is_err());

        let mut strict_pack = pack.clone();
        strict_pack
            .fabrication_authorization_policy
            .as_mut()
            .unwrap()
            .maximum_validity_seconds = 300;
        let strict_evidence = sample_evidence(&strict_pack);
        let signed = approvals(&strict_evidence, &strict_pack, &scope);
        let report =
            verify_fabrication_authorization(&strict_evidence, &strict_pack, &signed, 1_200)
                .unwrap();
        assert!(!report.fabrication_authorized);
        assert_eq!(report.gate_failures.len(), 1);
        assert!(report.gate_failures[0].starts_with("fabrication_validity_exceeds_policy:"));
    }

    #[test]
    fn report_rebinds_the_complete_policy_pack_and_signing_enforces_dedicated_trust() {
        let pack = policy();
        let evidence = sample_evidence(&pack);
        let scope = scope();
        assert!(
            sign_fabrication_approval(
                &evidence,
                &pack,
                &scope,
                FabricationApprovalDecision::Approve,
                "Wrong private key.",
                "FAB-41",
                "fabrication-a",
                &[99; 32],
            )
            .is_err()
        );

        let signed = approvals(&evidence, &pack, &scope);
        let mut report =
            verify_fabrication_authorization(&evidence, &pack, &signed, 1_200).unwrap();
        report.policy_pack.description.push('!');
        assert!(validate_fabrication_authorization_report(&report).is_err());
    }

    #[test]
    fn schemas_are_closed_and_expose_truthful_boundaries() {
        let signed = signed_fabrication_approval_json_schema();
        assert_eq!(signed["additionalProperties"], false);
        assert_eq!(
            signed["properties"]["evidence"]["properties"]["factory_receipt"]["properties"]["quote_authenticity_verified"]
                ["const"],
            false
        );
        assert_eq!(
            signed["properties"]["scope"]["properties"]["challenge"]["pattern"],
            "^[0-9a-f]{64}$"
        );

        let report = fabrication_authorization_report_json_schema();
        assert_eq!(report["additionalProperties"], false);
        assert_eq!(
            report["properties"]["challenge_one_time_use_enforced"]["const"],
            false
        );
        assert_eq!(
            report["properties"]["signed_approvals"]["items"]["additionalProperties"],
            false
        );
        assert!(report["properties"].get("policy_pack").is_some());
        assert!(report["properties"].get("gate_failures").is_some());
    }

    #[test]
    fn strict_parsers_reject_unknown_and_duplicate_fields() {
        let pack = policy();
        let evidence = sample_evidence(&pack);
        let signed = approvals(&evidence, &pack, &scope()).remove(0);
        let mut value = serde_json::to_value(&signed).unwrap();
        value["unexpected"] = json!(true);
        assert!(parse_signed_fabrication_approval(&value.to_string()).is_err());

        let source = serde_json::to_string(&signed).unwrap();
        let duplicate = source.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        assert!(parse_signed_fabrication_approval(&duplicate).is_err());
    }
}
