//! Policy-pinned Ed25519 attestation for one exact normalized factory receipt.
//!
//! This module authenticates receipt bytes to a dedicated key selected by an
//! externally pinned organization policy. It does not contact a factory,
//! authenticate a legal entity, attest TLS or raw response bytes, reserve
//! capacity, submit an order, or perform payment.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::fabrication_authorization::{MAX_FACTORY_RECEIPT_BYTES, MAX_POLICY_PACK_BYTES};
use crate::factory::{
    FactoryProvider, FactorySubmissionReceipt, factory_feedback_passed,
    validate_factory_submission_receipt, validate_manufacturing_package,
};
use crate::manufacturing_limits::MAX_PACKAGE_BYTES;
use crate::policy_pack::{
    FactoryReceiptAttestationPolicy, OrganizationPolicyPack, TrustedFactoryReceiptKey,
    policy_pack_sha256, validate_policy_pack,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) const SIGNED_FACTORY_RECEIPT_ATTESTATION_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RECEIPT_ATTESTATION_REPORT_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RECEIPT_ATTESTATION_SCOPE: &str =
    "policy-pinned-signed-factory-receipt-v1";
pub(crate) const MAX_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES: u64 = 1024 * 1024;
pub(crate) const MAX_FACTORY_RECEIPT_ATTESTATION_REPORT_BYTES: u64 = 4 * 1024 * 1024;

const SIGNATURE_DOMAIN: &str = "pcbex-factory-receipt-attestation-v1";
const REPORT_BINDING_DOMAIN: &[u8] = b"pcbex:factory-receipt-attestation-report:v1\0";
const MAXIMUM_VALIDITY_SECONDS: u64 = 604_800;
const MAXIMUM_TEXT_BYTES: usize = 4_096;
const MAXIMUM_ENDPOINT_BYTES: usize = 2_048;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReceiptPolicyEvidence {
    pub(crate) source: ExactArtifactIdentity,
    pub(crate) canonical_sha256: String,
    pub(crate) id: String,
    pub(crate) revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReceiptAttestationEvidence {
    pub(crate) manufacturing_package: ExactArtifactIdentity,
    pub(crate) factory_receipt: ExactArtifactIdentity,
    pub(crate) provider: FactoryProvider,
    pub(crate) adapter: String,
    pub(crate) endpoint: String,
    pub(crate) response_sha256: String,
    pub(crate) response_bytes: u64,
    pub(crate) http_status: u16,
    pub(crate) status: String,
    pub(crate) accepted: bool,
    pub(crate) dfm_passed: bool,
    pub(crate) quote_sha256: String,
    pub(crate) policy_pack: FactoryReceiptPolicyEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReceiptAttestationWindow {
    pub(crate) attestation_id: String,
    pub(crate) challenge: String,
    pub(crate) issued_at_unix: u64,
    pub(crate) expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReceiptAttestation {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) evidence: FactoryReceiptAttestationEvidence,
    pub(crate) attestation: FactoryReceiptAttestationWindow,
    pub(crate) factory_id: String,
    pub(crate) algorithm: String,
    pub(crate) public_key: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReceiptAttestationSigner {
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) public_key: String,
    pub(crate) attestation_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReceiptAttestationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) signature_verified: bool,
    pub(crate) policy_pack_pin_matched: bool,
    pub(crate) attestation_active: bool,
    pub(crate) factory_receipt_authenticity_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) endpoint_transport_authenticity_verified: bool,
    pub(crate) raw_response_authenticity_verified: bool,
    pub(crate) external_submission_performed: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) challenge_one_time_use_enforced: bool,
    pub(crate) evidence: FactoryReceiptAttestationEvidence,
    pub(crate) attestation: FactoryReceiptAttestationWindow,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) signer: FactoryReceiptAttestationSigner,
    pub(crate) signed_attestation: SignedFactoryReceiptAttestation,
    pub(crate) gate_failures: Vec<String>,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct SignaturePayload<'a> {
    domain: &'static str,
    schema_version: u32,
    verification_scope: &'static str,
    evidence: &'a FactoryReceiptAttestationEvidence,
    attestation: &'a FactoryReceiptAttestationWindow,
    factory_id: &'a str,
    algorithm: &'static str,
    public_key: &'a str,
}

#[derive(Serialize)]
struct ReportBindingPayload<'a> {
    schema_version: u32,
    verification_scope: &'a str,
    status: &'a str,
    signature_verified: bool,
    policy_pack_pin_matched: bool,
    attestation_active: bool,
    factory_receipt_authenticity_verified: bool,
    trusted_time_verified: bool,
    factory_legal_identity_verified: bool,
    endpoint_transport_authenticity_verified: bool,
    raw_response_authenticity_verified: bool,
    external_submission_performed: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    challenge_one_time_use_enforced: bool,
    evidence: &'a FactoryReceiptAttestationEvidence,
    attestation: &'a FactoryReceiptAttestationWindow,
    evaluated_at_unix: u64,
    signer: &'a FactoryReceiptAttestationSigner,
    signed_attestation: &'a SignedFactoryReceiptAttestation,
    gate_failures: &'a [String],
}

pub(crate) fn capture_factory_receipt_attestation_evidence(
    manufacturing_package: &[u8],
    factory_receipt: &[u8],
    policy_pack_source: &[u8],
    expected_policy_pack_canonical_sha256: &str,
) -> Result<(FactoryReceiptAttestationEvidence, OrganizationPolicyPack), String> {
    validate_digest(
        expected_policy_pack_canonical_sha256,
        "expected canonical policy pack SHA-256",
    )?;
    validate_manufacturing_package(manufacturing_package)
        .map_err(|error| format!("invalid manufacturing package: {error}"))?;
    let package_identity = exact_identity(manufacturing_package);
    validate_artifact_identity(
        &package_identity,
        MAX_PACKAGE_BYTES,
        "manufacturing package",
    )?;

    reject_duplicate_json_keys(factory_receipt)
        .map_err(|error| format!("invalid factory receipt JSON: {error:#}"))?;
    let receipt: FactorySubmissionReceipt = serde_json::from_slice(factory_receipt)
        .map_err(|error| format!("invalid factory receipt JSON: {error}"))?;
    validate_factory_submission_receipt(&receipt, false)
        .map_err(|error| format!("invalid factory receipt: {error}"))?;
    let receipt_identity = exact_identity(factory_receipt);
    validate_artifact_identity(
        &receipt_identity,
        MAX_FACTORY_RECEIPT_BYTES,
        "factory receipt",
    )?;
    if receipt.package_bytes != package_identity.bytes
        || receipt.package_sha256 != package_identity.sha256
        || receipt.request_sha256 != package_identity.sha256
    {
        return Err("factory receipt does not bind the exact manufacturing package".into());
    }
    if !factory_feedback_passed(&receipt) {
        return Err("factory receipt is not an accepted passing DFM result".into());
    }
    let quote = receipt
        .quote
        .as_ref()
        .filter(|quote| quote.is_object())
        .ok_or_else(|| "factory receipt must contain one opaque quote object".to_string())?;

    reject_duplicate_json_keys(policy_pack_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error:#}"))?;
    let policy_pack: OrganizationPolicyPack = serde_json::from_slice(policy_pack_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error}"))?;
    validate_policy_pack(&policy_pack)?;
    if policy_pack.factory_receipt_attestation_policy.is_none() {
        return Err("organization policy pack has no factory receipt attestation policy".into());
    }
    let canonical_sha256 = policy_pack_sha256(&policy_pack)?;
    if canonical_sha256 != expected_policy_pack_canonical_sha256 {
        return Err("organization policy pack does not match the expected canonical digest".into());
    }
    let policy_identity = exact_identity(policy_pack_source);
    validate_artifact_identity(
        &policy_identity,
        MAX_POLICY_PACK_BYTES,
        "organization policy pack",
    )?;

    let evidence = FactoryReceiptAttestationEvidence {
        manufacturing_package: package_identity,
        factory_receipt: receipt_identity,
        provider: receipt.provider,
        adapter: receipt.adapter,
        endpoint: receipt.endpoint,
        response_sha256: receipt.response_sha256,
        response_bytes: receipt.response_bytes,
        http_status: receipt.http_status,
        status: receipt.status,
        accepted: receipt.accepted,
        dfm_passed: receipt.dfm_passed == Some(true),
        quote_sha256: canonical_json_sha256(quote, "factory quote")?,
        policy_pack: FactoryReceiptPolicyEvidence {
            source: policy_identity,
            canonical_sha256,
            id: policy_pack.id.clone(),
            revision: policy_pack.revision,
        },
    };
    validate_factory_receipt_attestation_evidence(&evidence)?;
    validate_policy_binding(&evidence, &policy_pack)?;
    Ok((evidence, policy_pack))
}

pub(crate) fn validate_factory_receipt_attestation_signing_inputs(
    evidence: &FactoryReceiptAttestationEvidence,
    policy_pack: &OrganizationPolicyPack,
    attestation: &FactoryReceiptAttestationWindow,
    factory_id: &str,
) -> Result<(), String> {
    validate_factory_receipt_attestation_evidence(evidence)?;
    validate_policy_binding(evidence, policy_pack)?;
    validate_attestation_window(attestation)?;
    let trusted = trusted_factory(policy_pack, factory_id)?;
    if trusted.provider != provider_name(evidence.provider) {
        return Err("trusted factory provider does not match the exact receipt provider".into());
    }
    Ok(())
}

pub(crate) fn sign_factory_receipt_attestation(
    evidence: &FactoryReceiptAttestationEvidence,
    policy_pack: &OrganizationPolicyPack,
    attestation: &FactoryReceiptAttestationWindow,
    factory_id: &str,
    secret_key: &[u8; 32],
) -> Result<SignedFactoryReceiptAttestation, String> {
    validate_factory_receipt_attestation_signing_inputs(
        evidence,
        policy_pack,
        attestation,
        factory_id,
    )?;
    let trusted = trusted_factory(policy_pack, factory_id)?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if public_key != trusted.public_key {
        return Err("factory receipt private key does not match its policy-trusted key".into());
    }
    let payload = signature_payload(evidence, attestation, factory_id, &public_key)?;
    let signed = SignedFactoryReceiptAttestation {
        schema_version: SIGNED_FACTORY_RECEIPT_ATTESTATION_SCHEMA_VERSION,
        verification_scope: FACTORY_RECEIPT_ATTESTATION_SCOPE.into(),
        evidence: evidence.clone(),
        attestation: attestation.clone(),
        factory_id: factory_id.into(),
        algorithm: "ed25519".into(),
        public_key,
        signature: hex::encode(signing_key.sign(&payload).to_bytes()),
    };
    validate_signed_factory_receipt_attestation(&signed)?;
    Ok(signed)
}

pub(crate) fn verify_factory_receipt_attestation(
    evidence: &FactoryReceiptAttestationEvidence,
    policy_pack: &OrganizationPolicyPack,
    signed: &SignedFactoryReceiptAttestation,
    evaluated_at_unix: u64,
) -> Result<FactoryReceiptAttestationReport, String> {
    validate_factory_receipt_attestation_evidence(evidence)?;
    validate_policy_binding(evidence, policy_pack)?;
    validate_signed_factory_receipt_attestation(signed)?;
    if &signed.evidence != evidence {
        return Err("signed factory receipt does not bind the exact supplied evidence".into());
    }
    let trusted = trusted_factory(policy_pack, &signed.factory_id)?;
    if trusted.provider != provider_name(evidence.provider) {
        return Err("signed factory receipt provider does not match its policy key".into());
    }
    verify_signature(signed, trusted)?;
    let duration = validate_attestation_window(&signed.attestation)?;
    let policy = policy_pack
        .factory_receipt_attestation_policy
        .as_ref()
        .expect("validated factory receipt policy is present");
    let gate_failures =
        attestation_gate_failures(&signed.attestation, duration, policy, evaluated_at_unix);
    let active = gate_failures.is_empty();
    let signer = FactoryReceiptAttestationSigner {
        factory_id: signed.factory_id.clone(),
        provider: evidence.provider,
        public_key: signed.public_key.clone(),
        attestation_sha256: canonical_json_sha256(signed, "signed factory receipt attestation")?,
    };
    let mut report = FactoryReceiptAttestationReport {
        schema_version: FACTORY_RECEIPT_ATTESTATION_REPORT_SCHEMA_VERSION,
        verification_scope: FACTORY_RECEIPT_ATTESTATION_SCOPE.into(),
        status: if active {
            "receipt_authenticated"
        } else {
            "not_authenticated"
        }
        .into(),
        signature_verified: true,
        policy_pack_pin_matched: true,
        attestation_active: active,
        factory_receipt_authenticity_verified: active,
        trusted_time_verified: false,
        factory_legal_identity_verified: false,
        endpoint_transport_authenticity_verified: false,
        raw_response_authenticity_verified: false,
        external_submission_performed: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        challenge_one_time_use_enforced: false,
        evidence: evidence.clone(),
        attestation: signed.attestation.clone(),
        evaluated_at_unix,
        signer,
        signed_attestation: signed.clone(),
        gate_failures,
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    validate_factory_receipt_attestation_report(&report, policy_pack)?;
    Ok(report)
}

pub(crate) fn parse_signed_factory_receipt_attestation(
    source: &[u8],
) -> Result<SignedFactoryReceiptAttestation, String> {
    if source.len() as u64 > MAX_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES {
        return Err(format!(
            "signed factory receipt attestation exceeds {MAX_SIGNED_FACTORY_RECEIPT_ATTESTATION_BYTES} bytes"
        ));
    }
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid signed factory receipt attestation JSON: {error:#}"))?;
    let signed: SignedFactoryReceiptAttestation = serde_json::from_slice(source)
        .map_err(|error| format!("invalid signed factory receipt attestation JSON: {error}"))?;
    validate_signed_factory_receipt_attestation(&signed)?;
    Ok(signed)
}

pub(crate) fn validate_signed_factory_receipt_attestation(
    signed: &SignedFactoryReceiptAttestation,
) -> Result<(), String> {
    if signed.schema_version != SIGNED_FACTORY_RECEIPT_ATTESTATION_SCHEMA_VERSION
        || signed.verification_scope != FACTORY_RECEIPT_ATTESTATION_SCOPE
        || signed.algorithm != "ed25519"
    {
        return Err("signed factory receipt attestation header is invalid".into());
    }
    validate_factory_receipt_attestation_evidence(&signed.evidence)?;
    validate_attestation_window(&signed.attestation)?;
    validate_slug("factory receipt signer id", &signed.factory_id)?;
    let key = decode_hex_array::<32>(&signed.public_key, "factory receipt public key")?;
    let verifying = VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid factory receipt public key: {error}"))?;
    if verifying.is_weak() {
        return Err("factory receipt public key is weak".into());
    }
    decode_hex_array::<64>(&signed.signature, "factory receipt signature")?;
    Ok(())
}

pub(crate) fn validate_factory_receipt_attestation_report(
    report: &FactoryReceiptAttestationReport,
    policy_pack: &OrganizationPolicyPack,
) -> Result<(), String> {
    if report.schema_version != FACTORY_RECEIPT_ATTESTATION_REPORT_SCHEMA_VERSION
        || report.verification_scope != FACTORY_RECEIPT_ATTESTATION_SCOPE
        || !report.signature_verified
        || !report.policy_pack_pin_matched
        || report.trusted_time_verified
        || report.factory_legal_identity_verified
        || report.endpoint_transport_authenticity_verified
        || report.raw_response_authenticity_verified
        || report.external_submission_performed
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.challenge_one_time_use_enforced
    {
        return Err("factory receipt attestation report boundary is invalid".into());
    }
    validate_factory_receipt_attestation_evidence(&report.evidence)?;
    validate_policy_binding(&report.evidence, policy_pack)?;
    validate_signed_factory_receipt_attestation(&report.signed_attestation)?;
    if report.signed_attestation.evidence != report.evidence
        || report.signed_attestation.attestation != report.attestation
        || report.signer.factory_id != report.signed_attestation.factory_id
        || report.signer.public_key != report.signed_attestation.public_key
        || report.signer.provider != report.evidence.provider
    {
        return Err(
            "factory receipt attestation report does not retain its exact signature".into(),
        );
    }
    let trusted = trusted_factory(policy_pack, &report.signer.factory_id)?;
    verify_signature(&report.signed_attestation, trusted)?;
    if report.signer.attestation_sha256
        != canonical_json_sha256(
            &report.signed_attestation,
            "retained signed factory receipt attestation",
        )?
    {
        return Err("factory receipt attestation signer digest is invalid".into());
    }
    let duration = validate_attestation_window(&report.attestation)?;
    let policy = policy_pack
        .factory_receipt_attestation_policy
        .as_ref()
        .expect("validated factory receipt policy is present");
    let expected_gates = attestation_gate_failures(
        &report.attestation,
        duration,
        policy,
        report.evaluated_at_unix,
    );
    let active = expected_gates.is_empty();
    if report.gate_failures != expected_gates
        || report.attestation_active != active
        || report.factory_receipt_authenticity_verified != active
        || report.status
            != if active {
                "receipt_authenticated"
            } else {
                "not_authenticated"
            }
        || report.binding_sha256 != report_binding(report)?
    {
        return Err("factory receipt attestation report decision or binding is invalid".into());
    }
    Ok(())
}

fn validate_factory_receipt_attestation_evidence(
    evidence: &FactoryReceiptAttestationEvidence,
) -> Result<(), String> {
    validate_artifact_identity(
        &evidence.manufacturing_package,
        MAX_PACKAGE_BYTES,
        "manufacturing package",
    )?;
    validate_artifact_identity(
        &evidence.factory_receipt,
        MAX_FACTORY_RECEIPT_BYTES,
        "factory receipt",
    )?;
    validate_text(&evidence.adapter, 128, "factory receipt adapter")?;
    if evidence.adapter != provider_adapter_name(evidence.provider) {
        return Err("factory receipt adapter does not match its provider".into());
    }
    validate_text(
        &evidence.endpoint,
        MAXIMUM_ENDPOINT_BYTES,
        "factory receipt endpoint",
    )?;
    if !evidence.endpoint.starts_with("https://") {
        return Err("authenticated factory receipt endpoint must use HTTPS".into());
    }
    validate_digest(&evidence.response_sha256, "factory response SHA-256")?;
    if evidence.response_bytes == 0 || evidence.response_bytes > 64 * 1024 * 1024 {
        return Err("factory response byte count is outside its bound".into());
    }
    if !(200..=299).contains(&evidence.http_status) {
        return Err("authenticated factory receipt must retain a successful HTTP status".into());
    }
    validate_text(
        &evidence.status,
        MAXIMUM_TEXT_BYTES,
        "factory receipt status",
    )?;
    if !evidence.accepted || !evidence.dfm_passed {
        return Err(
            "authenticated factory receipt must retain accepted passing DFM evidence".into(),
        );
    }
    validate_digest(&evidence.quote_sha256, "canonical factory quote SHA-256")?;
    validate_artifact_identity(
        &evidence.policy_pack.source,
        MAX_POLICY_PACK_BYTES,
        "organization policy pack",
    )?;
    validate_digest(
        &evidence.policy_pack.canonical_sha256,
        "canonical policy pack SHA-256",
    )?;
    validate_slug("factory receipt policy pack id", &evidence.policy_pack.id)?;
    if evidence.policy_pack.revision == 0 {
        return Err("factory receipt policy pack revision must be greater than zero".into());
    }
    Ok(())
}

fn validate_policy_binding(
    evidence: &FactoryReceiptAttestationEvidence,
    policy_pack: &OrganizationPolicyPack,
) -> Result<(), String> {
    validate_policy_pack(policy_pack)?;
    if policy_pack.factory_receipt_attestation_policy.is_none() {
        return Err("organization policy pack has no factory receipt attestation policy".into());
    }
    if evidence.policy_pack.id != policy_pack.id
        || evidence.policy_pack.revision != policy_pack.revision
        || evidence.policy_pack.canonical_sha256 != policy_pack_sha256(policy_pack)?
    {
        return Err("factory receipt evidence does not bind the supplied policy pack".into());
    }
    Ok(())
}

fn trusted_factory<'a>(
    policy_pack: &'a OrganizationPolicyPack,
    factory_id: &str,
) -> Result<&'a TrustedFactoryReceiptKey, String> {
    policy_pack
        .factory_receipt_attestation_policy
        .as_ref()
        .ok_or_else(|| {
            "organization policy pack has no factory receipt attestation policy".to_string()
        })?
        .trusted_keys
        .iter()
        .find(|trusted| trusted.factory_id == factory_id)
        .ok_or_else(|| format!("factory {factory_id:?} is not trusted for receipt attestation"))
}

fn validate_attestation_window(window: &FactoryReceiptAttestationWindow) -> Result<u64, String> {
    validate_slug("factory receipt attestation id", &window.attestation_id)?;
    validate_digest(&window.challenge, "factory receipt attestation challenge")?;
    let duration = window
        .expires_at_unix
        .checked_sub(window.issued_at_unix)
        .ok_or_else(|| "factory receipt attestation expiry precedes issuance".to_string())?;
    if duration == 0 || duration > MAXIMUM_VALIDITY_SECONDS {
        return Err(format!(
            "factory receipt attestation window must be 1 to {MAXIMUM_VALIDITY_SECONDS} seconds"
        ));
    }
    Ok(duration)
}

fn attestation_gate_failures(
    window: &FactoryReceiptAttestationWindow,
    duration: u64,
    policy: &FactoryReceiptAttestationPolicy,
    evaluated_at_unix: u64,
) -> Vec<String> {
    let mut failures = Vec::new();
    if duration > policy.maximum_validity_seconds {
        failures.push(format!(
            "factory_receipt_validity_exceeds_policy:maximum_seconds={}:actual_seconds={duration}",
            policy.maximum_validity_seconds
        ));
    }
    if evaluated_at_unix < window.issued_at_unix || evaluated_at_unix > window.expires_at_unix {
        failures.push("factory_receipt_attestation_window_inactive".into());
    }
    failures.sort();
    failures
}

fn verify_signature(
    signed: &SignedFactoryReceiptAttestation,
    trusted: &TrustedFactoryReceiptKey,
) -> Result<(), String> {
    if signed.public_key != trusted.public_key {
        return Err("factory receipt attestation key does not match its trusted policy key".into());
    }
    let public_key = decode_hex_array::<32>(&signed.public_key, "factory receipt public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid factory receipt public key: {error}"))?;
    if verifying_key.is_weak() {
        return Err("factory receipt public key is weak".into());
    }
    let signature = Signature::from_bytes(&decode_hex_array::<64>(
        &signed.signature,
        "factory receipt signature",
    )?);
    let payload = signature_payload(
        &signed.evidence,
        &signed.attestation,
        &signed.factory_id,
        &signed.public_key,
    )?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|error| format!("invalid factory receipt attestation signature: {error}"))
}

fn signature_payload(
    evidence: &FactoryReceiptAttestationEvidence,
    attestation: &FactoryReceiptAttestationWindow,
    factory_id: &str,
    public_key: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&SignaturePayload {
        domain: SIGNATURE_DOMAIN,
        schema_version: SIGNED_FACTORY_RECEIPT_ATTESTATION_SCHEMA_VERSION,
        verification_scope: FACTORY_RECEIPT_ATTESTATION_SCOPE,
        evidence,
        attestation,
        factory_id,
        algorithm: "ed25519",
        public_key,
    })
    .map_err(|error| format!("serializing factory receipt signature payload: {error}"))
}

fn report_binding(report: &FactoryReceiptAttestationReport) -> Result<String, String> {
    let payload = ReportBindingPayload {
        schema_version: report.schema_version,
        verification_scope: &report.verification_scope,
        status: &report.status,
        signature_verified: report.signature_verified,
        policy_pack_pin_matched: report.policy_pack_pin_matched,
        attestation_active: report.attestation_active,
        factory_receipt_authenticity_verified: report.factory_receipt_authenticity_verified,
        trusted_time_verified: report.trusted_time_verified,
        factory_legal_identity_verified: report.factory_legal_identity_verified,
        endpoint_transport_authenticity_verified: report.endpoint_transport_authenticity_verified,
        raw_response_authenticity_verified: report.raw_response_authenticity_verified,
        external_submission_performed: report.external_submission_performed,
        capacity_reserved: report.capacity_reserved,
        order_placed: report.order_placed,
        payment_performed: report.payment_performed,
        challenge_one_time_use_enforced: report.challenge_one_time_use_enforced,
        evidence: &report.evidence,
        attestation: &report.attestation,
        evaluated_at_unix: report.evaluated_at_unix,
        signer: &report.signer,
        signed_attestation: &report.signed_attestation,
        gate_failures: &report.gate_failures,
    };
    let encoded = serde_json::to_vec(&payload)
        .map_err(|error| format!("serializing factory receipt report binding: {error}"))?;
    let mut digest = Sha256::new();
    digest.update(REPORT_BINDING_DOMAIN);
    digest.update(encoded);
    Ok(hex::encode(digest.finalize()))
}

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: hex::encode(Sha256::digest(source)),
    }
}

fn canonical_json_sha256<T: Serialize>(value: &T, label: &str) -> Result<String, String> {
    let encoded = serde_json::to_vec(value)
        .map_err(|error| format!("serializing {label} for canonical digest: {error}"))?;
    Ok(hex::encode(Sha256::digest(encoded)))
}

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    maximum: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum {
        return Err(format!("{label} byte count is outside its closed bound"));
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
            "{label} must contain 64 lowercase hexadecimal characters"
        ));
    }
    Ok(())
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
        Err(format!("{label} must match [a-z0-9][a-z0-9.-]{{0,127}}"))
    }
}

fn validate_text(value: &str, maximum: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.as_bytes().contains(&0) || value.len() > maximum {
        Err(format!(
            "{label} must contain 1 to {maximum} non-NUL UTF-8 bytes"
        ))
    } else {
        Ok(())
    }
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} must contain {} lowercase hexadecimal characters",
            N * 2
        ));
    }
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(decoded)
}

fn provider_name(provider: FactoryProvider) -> &'static str {
    match provider {
        FactoryProvider::Jlcpcb => "jlcpcb",
        FactoryProvider::Pcbway => "pcbway",
        FactoryProvider::Generic => "generic",
    }
}

fn provider_adapter_name(provider: FactoryProvider) -> &'static str {
    match provider {
        FactoryProvider::Jlcpcb => "jlcpcb-http-v1",
        FactoryProvider::Pcbway => "pcbway-http-v1",
        FactoryProvider::Generic => "generic-factory-http-v1",
    }
}

fn identity_schema(maximum: u64) -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
}

fn evidence_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": [
            "manufacturing_package", "factory_receipt", "provider", "adapter", "endpoint",
            "response_sha256", "response_bytes", "http_status", "status", "accepted",
            "dfm_passed", "quote_sha256", "policy_pack"
        ],
        "properties": {
            "manufacturing_package": identity_schema(MAX_PACKAGE_BYTES),
            "factory_receipt": identity_schema(MAX_FACTORY_RECEIPT_BYTES),
            "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
            "adapter": {"type": "string", "minLength": 1, "maxLength": 128},
            "endpoint": {"type": "string", "pattern": "^https://", "maxLength": MAXIMUM_ENDPOINT_BYTES},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": 67108864},
            "http_status": {"type": "integer", "minimum": 200, "maximum": 299},
            "status": {"type": "string", "minLength": 1, "maxLength": MAXIMUM_TEXT_BYTES},
            "accepted": {"const": true},
            "dfm_passed": {"const": true},
            "quote_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "policy_pack": {
                "type": "object", "additionalProperties": false,
                "required": ["source", "canonical_sha256", "id", "revision"],
                "properties": {
                    "source": identity_schema(MAX_POLICY_PACK_BYTES),
                    "canonical_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "revision": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64}
                }
            }
        }
    })
}

fn window_schema() -> Value {
    json!({
        "type": "object", "additionalProperties": false,
        "required": ["attestation_id", "challenge", "issued_at_unix", "expires_at_unix"],
        "properties": {
            "attestation_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "challenge": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "issued_at_unix": {"type": "integer", "minimum": 0, "maximum": 18446744073709551615_u64},
            "expires_at_unix": {"type": "integer", "minimum": 1, "maximum": 18446744073709551615_u64}
        }
    })
}

pub(crate) fn signed_factory_receipt_attestation_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-receipt-attestation-v1.json",
        "title": "pcbex policy-pinned signed factory receipt attestation",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "evidence", "attestation",
            "factory_id", "algorithm", "public_key", "signature"
        ],
        "properties": {
            "schema_version": {"const": SIGNED_FACTORY_RECEIPT_ATTESTATION_SCHEMA_VERSION},
            "verification_scope": {"const": FACTORY_RECEIPT_ATTESTATION_SCOPE},
            "evidence": evidence_schema(),
            "attestation": window_schema(),
            "factory_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "algorithm": {"const": "ed25519"},
            "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signature": {"type": "string", "pattern": "^[0-9a-f]{128}$"}
        }
    })
}

pub(crate) fn factory_receipt_attestation_report_json_schema() -> Value {
    let signed = signed_factory_receipt_attestation_json_schema();
    let false_claims = [
        "trusted_time_verified",
        "factory_legal_identity_verified",
        "endpoint_transport_authenticity_verified",
        "raw_response_authenticity_verified",
        "external_submission_performed",
        "capacity_reserved",
        "order_placed",
        "payment_performed",
        "challenge_one_time_use_enforced",
    ];
    let mut properties = serde_json::Map::new();
    properties.insert(
        "schema_version".into(),
        json!({"const": FACTORY_RECEIPT_ATTESTATION_REPORT_SCHEMA_VERSION}),
    );
    properties.insert(
        "verification_scope".into(),
        json!({"const": FACTORY_RECEIPT_ATTESTATION_SCOPE}),
    );
    properties.insert(
        "status".into(),
        json!({"enum": ["receipt_authenticated", "not_authenticated"]}),
    );
    properties.insert("signature_verified".into(), json!({"const": true}));
    properties.insert("policy_pack_pin_matched".into(), json!({"const": true}));
    properties.insert("attestation_active".into(), json!({"type": "boolean"}));
    properties.insert(
        "factory_receipt_authenticity_verified".into(),
        json!({"type": "boolean"}),
    );
    for key in false_claims {
        properties.insert(key.into(), json!({"const": false}));
    }
    properties.insert("evidence".into(), evidence_schema());
    properties.insert("attestation".into(), window_schema());
    properties.insert(
        "evaluated_at_unix".into(),
        json!({"type": "integer", "minimum": 0, "maximum": 18446744073709551615_u64}),
    );
    properties.insert(
        "signer".into(),
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["factory_id", "provider", "public_key", "attestation_sha256"],
            "properties": {
                "factory_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
                "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "attestation_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
            }
        }),
    );
    properties.insert("signed_attestation".into(), signed);
    properties.insert(
        "gate_failures".into(),
        json!({
            "type": "array", "maxItems": 2,
            "items": {"type": "string", "maxLength": 256}
        }),
    );
    properties.insert(
        "binding_sha256".into(),
        json!({"type": "string", "pattern": "^[0-9a-f]{64}$"}),
    );
    let required = properties.keys().cloned().collect::<Vec<_>>();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-receipt-attestation-report-v1.json",
        "title": "pcbex factory receipt attestation verification report",
        "type": "object", "additionalProperties": false,
        "required": required,
        "properties": properties,
        "allOf": [{
            "if": {"properties": {"status": {"const": "receipt_authenticated"}}},
            "then": {"properties": {
                "attestation_active": {"const": true},
                "factory_receipt_authenticity_verified": {"const": true},
                "gate_failures": {"maxItems": 0}
            }},
            "else": {"properties": {
                "attestation_active": {"const": false},
                "factory_receipt_authenticity_verified": {"const": false},
                "gate_failures": {"minItems": 1}
            }}
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_pack::{FactoryReceiptAttestationPolicy, parse_policy_pack};

    fn policy() -> OrganizationPolicyPack {
        let mut policy =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        policy.factory_receipt_attestation_policy = Some(FactoryReceiptAttestationPolicy {
            maximum_validity_seconds: 600,
            trusted_keys: vec![TrustedFactoryReceiptKey {
                factory_id: "factory-a".into(),
                provider: "generic".into(),
                public_key: hex::encode(
                    SigningKey::from_bytes(&[71; 32]).verifying_key().to_bytes(),
                ),
            }],
        });
        validate_policy_pack(&policy).unwrap();
        policy
    }

    fn evidence(policy: &OrganizationPolicyPack) -> FactoryReceiptAttestationEvidence {
        FactoryReceiptAttestationEvidence {
            manufacturing_package: ExactArtifactIdentity {
                bytes: 100,
                sha256: "1".repeat(64),
            },
            factory_receipt: ExactArtifactIdentity {
                bytes: 200,
                sha256: "2".repeat(64),
            },
            provider: FactoryProvider::Generic,
            adapter: "generic-factory-http-v1".into(),
            endpoint: "https://factory.example/quote".into(),
            response_sha256: "3".repeat(64),
            response_bytes: 300,
            http_status: 200,
            status: "accepted".into(),
            accepted: true,
            dfm_passed: true,
            quote_sha256: "4".repeat(64),
            policy_pack: FactoryReceiptPolicyEvidence {
                source: ExactArtifactIdentity {
                    bytes: 400,
                    sha256: "5".repeat(64),
                },
                canonical_sha256: policy_pack_sha256(policy).unwrap(),
                id: policy.id.clone(),
                revision: policy.revision,
            },
        }
    }

    fn window() -> FactoryReceiptAttestationWindow {
        FactoryReceiptAttestationWindow {
            attestation_id: "receipt-71".into(),
            challenge: "6".repeat(64),
            issued_at_unix: 1_000,
            expires_at_unix: 1_600,
        }
    }

    #[test]
    fn signs_verifies_and_retains_an_inactive_window() {
        let policy = policy();
        let evidence = evidence(&policy);
        let signed =
            sign_factory_receipt_attestation(&evidence, &policy, &window(), "factory-a", &[71; 32])
                .unwrap();
        assert_eq!(
            signed.signature,
            "29818f084cc66158c4faba7ddc6a465fe10279547aa560388c84b2634f7e880f3a694181b95733e4ad0b9c0277383af11e9d2d2bf2f73bd7c2a7d2f45582830e"
        );
        let positive =
            verify_factory_receipt_attestation(&evidence, &policy, &signed, 1_100).unwrap();
        assert_eq!(positive.status, "receipt_authenticated");
        assert!(positive.factory_receipt_authenticity_verified);
        assert!(positive.gate_failures.is_empty());
        validate_factory_receipt_attestation_report(&positive, &policy).unwrap();

        let negative =
            verify_factory_receipt_attestation(&evidence, &policy, &signed, 1_700).unwrap();
        assert_eq!(negative.status, "not_authenticated");
        assert!(!negative.factory_receipt_authenticity_verified);
        assert_eq!(
            negative.gate_failures,
            vec!["factory_receipt_attestation_window_inactive"]
        );

        let mut policy_limited_window = window();
        policy_limited_window.expires_at_unix += 1;
        let policy_limited = sign_factory_receipt_attestation(
            &evidence,
            &policy,
            &policy_limited_window,
            "factory-a",
            &[71; 32],
        )
        .unwrap();
        let policy_negative =
            verify_factory_receipt_attestation(&evidence, &policy, &policy_limited, 1_100).unwrap();
        assert_eq!(
            policy_negative.gate_failures,
            vec!["factory_receipt_validity_exceeds_policy:maximum_seconds=600:actual_seconds=601"]
        );
    }

    #[test]
    fn rejects_tampering_and_closes_schemas() {
        let policy = policy();
        let evidence = evidence(&policy);
        let mut signed =
            sign_factory_receipt_attestation(&evidence, &policy, &window(), "factory-a", &[71; 32])
                .unwrap();
        signed.evidence.quote_sha256 = "f".repeat(64);
        assert!(
            verify_factory_receipt_attestation(&signed.evidence, &policy, &signed, 1_100)
                .unwrap_err()
                .contains("invalid factory receipt attestation signature")
        );
        let signed_schema = signed_factory_receipt_attestation_json_schema();
        let report_schema = factory_receipt_attestation_report_json_schema();
        assert_eq!(signed_schema["additionalProperties"], false);
        assert_eq!(report_schema["additionalProperties"], false);
        assert_eq!(
            report_schema["properties"]["signed_attestation"]["additionalProperties"],
            false
        );

        fn audit_schema(value: &Value, objects: &mut usize, arrays: &mut usize) {
            match value {
                Value::Object(map) => {
                    if map.get("type") == Some(&Value::String("object".into())) {
                        *objects += 1;
                        assert_eq!(map.get("additionalProperties"), Some(&Value::Bool(false)));
                    }
                    if map.get("type") == Some(&Value::String("array".into())) {
                        *arrays += 1;
                        assert!(map.contains_key("maxItems"));
                    }
                    for child in map.values() {
                        audit_schema(child, objects, arrays);
                    }
                }
                Value::Array(values) => {
                    for child in values {
                        audit_schema(child, objects, arrays);
                    }
                }
                _ => {}
            }
        }
        let mut total_arrays = 0;
        for schema in [&signed_schema, &report_schema] {
            let mut objects = 0;
            let mut arrays = 0;
            audit_schema(schema, &mut objects, &mut arrays);
            assert!(objects >= 5);
            total_arrays += arrays;
        }
        assert!(total_arrays >= 1);
    }
}
