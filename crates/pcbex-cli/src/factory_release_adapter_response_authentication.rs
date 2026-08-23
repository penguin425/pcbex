//! Policy-pinned authentication of durable factory-release adapter responses.
//!
//! The v1.482 intent and receipt remain byte-for-byte unchanged. This module
//! adds a strict RFC 9421 application profile around the same HTTP exchange,
//! verifies an RFC 9530 Content-Digest, and retains a separately bound outer
//! report. A response signature authenticates the covered application
//! response bytes; it does not prove legal identity, trusted time, capacity,
//! ordering, payment, or server-side exactly-once behavior.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::fabrication_authorization::MAX_POLICY_PACK_BYTES;
use crate::factory::{FactoryProvider, validate_bearer_token, validate_endpoint};
use crate::policy_pack::{
    FactoryAdapterResponseAuthenticationPolicy, OrganizationPolicyPack,
    TrustedFactoryAdapterResponseKey, policy_pack_sha256, validate_policy_pack,
};
#[cfg(test)]
use crate::signed_factory_receipt_release_submission::MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES;
use crate::signed_factory_receipt_release_submission::{
    FactoryReleaseAdapterOperation, SignedFactoryReleaseAdapterReceipt,
    SignedFactoryReleaseSubmissionIntent, parse_signed_factory_release_adapter_receipt,
    receipt_from_response, render_signed_factory_release_adapter_receipt,
    render_signed_factory_release_submission_intent,
    signed_factory_release_adapter_receipt_json_schema,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(test)]
use ed25519_dalek::{Signer, SigningKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub(crate) const FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCOPE: &str =
    "policy-pinned-rfc9421-factory-release-adapter-response-v1";
pub(crate) const FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE: &str =
    "pcbex-signed-factory-release-response-v1";
pub(crate) const FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL: &str = "pcbex";
pub(crate) const FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM: &str = "ed25519";
pub(crate) const FACTORY_RELEASE_ADAPTER_RESPONSE_PROFILE_HEADER: &str =
    "rfc9421-ed25519-content-digest-v1";
pub(crate) const MAX_FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_BYTES: u64 = 64 * 1024;

const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-adapter-response-authentication-report:v1\0";
const MAX_SIGNATURE_TIMESTAMP: u64 = 999_999_999_999_999;
const MAX_ENDPOINT_CHARS: usize = 2048;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterResponsePolicyEvidence {
    pub(crate) source: ExactArtifactIdentity,
    pub(crate) canonical_sha256: String,
    pub(crate) id: String,
    pub(crate) revision: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterResponseSigner {
    pub(crate) key_id: String,
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) public_key: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterHttpMessageSignature {
    pub(crate) profile: String,
    pub(crate) label: String,
    pub(crate) algorithm: String,
    pub(crate) key_id: String,
    pub(crate) created_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) content_digest: String,
    pub(crate) signature_input: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterResponseAuthenticationReport {
    pub(crate) schema_version: u32,
    pub(crate) authentication_scope: String,
    pub(crate) status: String,
    pub(crate) response_authenticated: bool,
    pub(crate) response_signature_verified: bool,
    pub(crate) response_content_digest_verified: bool,
    pub(crate) policy_pack_pin_matched: bool,
    pub(crate) signer_policy_matched: bool,
    pub(crate) signature_time_active: bool,
    pub(crate) acknowledgement_authenticated: bool,
    pub(crate) accepted: bool,
    pub(crate) raw_response_authenticity_verified: bool,
    pub(crate) endpoint_transport_authenticity_verified: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) server_side_idempotency_enforced: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) intent_sha256: String,
    pub(crate) adapter_receipt_sha256: String,
    pub(crate) policy_pack: FactoryReleaseAdapterResponsePolicyEvidence,
    pub(crate) signer: Option<FactoryReleaseAdapterResponseSigner>,
    pub(crate) response_signature: Option<FactoryReleaseAdapterHttpMessageSignature>,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) authentication_failure: Option<String>,
    pub(crate) adapter_receipt: SignedFactoryReleaseAdapterReceipt,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct ReportBinding<'a> {
    schema_version: u32,
    authentication_scope: &'a str,
    status: &'a str,
    response_authenticated: bool,
    response_signature_verified: bool,
    response_content_digest_verified: bool,
    policy_pack_pin_matched: bool,
    signer_policy_matched: bool,
    signature_time_active: bool,
    acknowledgement_authenticated: bool,
    accepted: bool,
    raw_response_authenticity_verified: bool,
    endpoint_transport_authenticity_verified: bool,
    factory_legal_identity_verified: bool,
    trusted_time_verified: bool,
    server_side_idempotency_enforced: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    exactly_once_execution_verified: bool,
    intent_sha256: &'a str,
    adapter_receipt_sha256: &'a str,
    policy_pack: &'a FactoryReleaseAdapterResponsePolicyEvidence,
    signer: &'a Option<FactoryReleaseAdapterResponseSigner>,
    response_signature: &'a Option<FactoryReleaseAdapterHttpMessageSignature>,
    evaluated_at_unix: u64,
    authentication_failure: &'a Option<String>,
    adapter_receipt: &'a SignedFactoryReleaseAdapterReceipt,
}

#[derive(Clone, Debug, Default)]
struct CapturedResponseHeaders {
    content_type: Option<String>,
    content_digest: Option<String>,
    signature_input: Option<String>,
    signature: Option<String>,
    failure: Option<&'static str>,
}

pub(crate) fn capture_factory_release_adapter_response_policy(
    policy_source: &[u8],
    expected_canonical_sha256: &str,
) -> Result<
    (
        FactoryReleaseAdapterResponsePolicyEvidence,
        OrganizationPolicyPack,
    ),
    String,
> {
    validate_digest(
        expected_canonical_sha256,
        "expected canonical adapter response policy SHA-256",
    )?;
    if policy_source.is_empty() || policy_source.len() as u64 > MAX_POLICY_PACK_BYTES {
        return Err(format!(
            "organization policy pack must contain 1 to {MAX_POLICY_PACK_BYTES} bytes"
        ));
    }
    reject_duplicate_json_keys(policy_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error:#}"))?;
    let policy: OrganizationPolicyPack = serde_json::from_slice(policy_source)
        .map_err(|error| format!("invalid organization policy pack JSON: {error}"))?;
    validate_policy_pack(&policy)?;
    if policy
        .factory_adapter_response_authentication_policy
        .is_none()
    {
        return Err(
            "organization policy pack has no factory adapter response authentication policy".into(),
        );
    }
    let canonical_sha256 = policy_pack_sha256(&policy)?;
    if canonical_sha256 != expected_canonical_sha256 {
        return Err("organization policy pack does not match the expected canonical digest".into());
    }
    let evidence = FactoryReleaseAdapterResponsePolicyEvidence {
        source: exact_identity(policy_source),
        canonical_sha256,
        id: policy.id.clone(),
        revision: policy.revision,
    };
    validate_policy_evidence(&evidence, &policy, policy_source)?;
    Ok((evidence, policy))
}

pub(crate) fn render_factory_release_adapter_response_authentication_report(
    report: &FactoryReleaseAdapterResponseAuthenticationReport,
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy_source: &[u8],
    expected_policy_sha256: &str,
) -> Result<Vec<u8>, String> {
    let (_, policy) =
        capture_factory_release_adapter_response_policy(policy_source, expected_policy_sha256)?;
    validate_factory_release_adapter_response_authentication_report(
        report,
        intent,
        &policy,
        policy_source,
    )?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_BYTES,
        "factory release adapter response authentication report",
    )
}

pub(crate) fn parse_factory_release_adapter_response_authentication_report(
    source: &[u8],
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy_source: &[u8],
    expected_policy_sha256: &str,
) -> Result<FactoryReleaseAdapterResponseAuthenticationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_BYTES,
        "factory release adapter response authentication report",
    )?;
    let (_, policy) =
        capture_factory_release_adapter_response_policy(policy_source, expected_policy_sha256)?;
    validate_factory_release_adapter_response_authentication_report(
        &report,
        intent,
        &policy,
        policy_source,
    )?;
    Ok(report)
}

pub(crate) fn authenticated_factory_release_submission_filename(
    idempotency_key: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    Ok(format!(
        "authenticated-factory-release-submission-v1-{idempotency_key}.json"
    ))
}

pub(crate) fn authenticated_factory_release_reconciliation_filename(
    idempotency_key: &str,
    reconciliation_id: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_digest(reconciliation_id, "factory release reconciliation id")?;
    Ok(format!(
        "authenticated-factory-release-reconciliation-v1-{idempotency_key}-{reconciliation_id}.json"
    ))
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(crate) fn sign_factory_release_adapter_http_response(
    intent: &SignedFactoryReleaseSubmissionIntent,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
    http_status: u16,
    response_body: &[u8],
    policy: &OrganizationPolicyPack,
    key_id: &str,
    secret_key: &[u8; 32],
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<FactoryReleaseAdapterHttpMessageSignature, String> {
    validate_signature_context(intent, operation, reconciliation_id, endpoint)?;
    if !(100..=599).contains(&http_status) {
        return Err("factory adapter response HTTP status is outside its bound".into());
    }
    if response_body.is_empty()
        || response_body.len() as u64 > MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES
    {
        return Err("factory adapter response body is outside its bound".into());
    }
    let trusted = trusted_response_key(policy, key_id)?;
    validate_trusted_response_key_binding(trusted, intent)?;
    validate_signature_window(
        created_at_unix,
        expires_at_unix,
        response_policy(policy)?,
        None,
    )?;
    let signing_key = SigningKey::from_bytes(secret_key);
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    if public_key != trusted.public_key {
        return Err("factory adapter response private key does not match its policy key".into());
    }

    let content_digest = content_digest(response_body);
    let signature_input = signature_input(operation, created_at_unix, expires_at_unix, key_id);
    let base = signature_base(
        intent,
        operation,
        reconciliation_id,
        endpoint,
        http_status,
        &content_digest,
        &signature_input,
    )?;
    let signature_bytes = signing_key.sign(base.as_bytes()).to_bytes();
    let signed = FactoryReleaseAdapterHttpMessageSignature {
        profile: FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE.into(),
        label: FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL.into(),
        algorithm: FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.into(),
        created_at_unix,
        expires_at_unix,
        content_digest,
        signature_input,
        signature: format!(
            "{}=:{}:",
            FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL,
            STANDARD.encode(signature_bytes)
        ),
    };
    validate_signature_evidence_shape(&signed, operation)?;
    Ok(signed)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn submit_authenticated_factory_release_adapter(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    package: &[u8],
    bearer_token: &str,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    attempted_at_unix: u64,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
) -> Result<
    (
        SignedFactoryReleaseAdapterReceipt,
        FactoryReleaseAdapterResponseAuthenticationReport,
    ),
    String,
> {
    validate_network_inputs(
        intent,
        intent_sha256,
        package,
        bearer_token,
        timeout_seconds,
        &intent.submission_endpoint,
        allow_http_loopback,
        policy_evidence,
        policy,
    )?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent: ureq::Agent = config.into();
    let response = agent
        .post(&intent.submission_endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/zip")
        .header("User-Agent", concat!("pcbex/", env!("CARGO_PKG_VERSION")))
        .header("X-PCBEX-Adapter", "signed-factory-release-http-v1")
        .header("X-PCBEX-Schema-Version", "1")
        .header(
            "X-PCBEX-Response-Signature-Profile",
            FACTORY_RELEASE_ADAPTER_RESPONSE_PROFILE_HEADER,
        )
        .header("Idempotency-Key", &intent.idempotency_key)
        .header("X-PCBEX-Request-Nonce", &intent.request_nonce)
        .header(
            "X-PCBEX-Release-Subject-SHA256",
            &intent.release_subject_sha256,
        )
        .header(
            "X-PCBEX-Package-SHA256",
            &intent.manufacturing_package.sha256,
        )
        .header("X-PCBEX-Factory-ID", &intent.factory_id)
        .header("Authorization", &format!("Bearer {bearer_token}"))
        .send(package);
    authenticate_network_response(
        intent,
        intent_sha256,
        FactoryReleaseAdapterOperation::Submit,
        None,
        &intent.submission_endpoint,
        bearer_token,
        attempted_at_unix,
        policy_evidence,
        policy,
        response,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_authenticated_factory_release_adapter(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    endpoint: &str,
    reconciliation_id: &str,
    bearer_token: &str,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    attempted_at_unix: u64,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
) -> Result<
    (
        SignedFactoryReleaseAdapterReceipt,
        FactoryReleaseAdapterResponseAuthenticationReport,
    ),
    String,
> {
    validate_digest(reconciliation_id, "factory release reconciliation id")?;
    validate_network_inputs(
        intent,
        intent_sha256,
        &[],
        bearer_token,
        timeout_seconds,
        endpoint,
        allow_http_loopback,
        policy_evidence,
        policy,
    )?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent: ureq::Agent = config.into();
    let response = agent
        .get(endpoint)
        .header("Accept", "application/json")
        .header("User-Agent", concat!("pcbex/", env!("CARGO_PKG_VERSION")))
        .header("X-PCBEX-Adapter", "signed-factory-release-http-v1")
        .header("X-PCBEX-Schema-Version", "1")
        .header(
            "X-PCBEX-Response-Signature-Profile",
            FACTORY_RELEASE_ADAPTER_RESPONSE_PROFILE_HEADER,
        )
        .header("Idempotency-Key", &intent.idempotency_key)
        .header("X-PCBEX-Request-Nonce", &intent.request_nonce)
        .header("X-PCBEX-Reconciliation-ID", reconciliation_id)
        .header(
            "X-PCBEX-Release-Subject-SHA256",
            &intent.release_subject_sha256,
        )
        .header(
            "X-PCBEX-Package-SHA256",
            &intent.manufacturing_package.sha256,
        )
        .header("X-PCBEX-Factory-ID", &intent.factory_id)
        .header("Authorization", &format!("Bearer {bearer_token}"))
        .call();
    authenticate_network_response(
        intent,
        intent_sha256,
        FactoryReleaseAdapterOperation::Reconcile,
        Some(reconciliation_id),
        endpoint,
        bearer_token,
        attempted_at_unix,
        policy_evidence,
        policy,
        response,
    )
}

#[allow(clippy::too_many_arguments)]
fn authenticate_network_response(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
    bearer_token: &str,
    attempted_at_unix: u64,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<
    (
        SignedFactoryReleaseAdapterReceipt,
        FactoryReleaseAdapterResponseAuthenticationReport,
    ),
    String,
> {
    let headers = match response.as_ref() {
        Ok(response) => capture_response_headers(response, bearer_token),
        Err(_) => CapturedResponseHeaders {
            failure: Some("transport_error"),
            ..CapturedResponseHeaders::default()
        },
    };
    let receipt = receipt_from_response(
        intent,
        intent_sha256,
        operation,
        reconciliation_id,
        endpoint,
        bearer_token,
        attempted_at_unix,
        response,
    )?;
    let evaluated_at_unix = crate::current_unix_seconds()
        .map_err(|error| format!("sampling adapter response verification time: {error:#}"))?;
    let report = authenticate_captured_response(
        intent,
        intent_sha256,
        &receipt,
        policy_evidence,
        policy,
        &headers,
        evaluated_at_unix,
    )?;
    Ok((receipt, report))
}

#[allow(clippy::too_many_arguments)]
fn authenticate_captured_response(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    receipt: &SignedFactoryReleaseAdapterReceipt,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
    headers: &CapturedResponseHeaders,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseAdapterResponseAuthenticationReport, String> {
    validate_timestamp(evaluated_at_unix, "adapter response evaluation timestamp")?;
    let intent_source = render_signed_factory_release_submission_intent(intent)?;
    if sha256(&intent_source) != intent_sha256 {
        return Err("factory release submission intent SHA-256 does not match its bytes".into());
    }
    let receipt_source = render_signed_factory_release_adapter_receipt(receipt)?;
    parse_signed_factory_release_adapter_receipt(&receipt_source, intent)?;
    let receipt_sha256 = sha256(&receipt_source);
    validate_policy_evidence_without_source(policy_evidence, policy)?;

    let negative = |failure: &str| {
        build_authentication_report(
            intent_sha256,
            &receipt_sha256,
            receipt,
            policy_evidence,
            None,
            None,
            evaluated_at_unix,
            Some(failure),
        )
    };
    if let Some(failure) = headers.failure {
        return negative(failure);
    }
    if receipt.failure.as_deref() == Some("credential_reflection_detected") {
        return negative("credential_reflection_detected");
    }
    let Some(response_sha256) = receipt.response_sha256.as_deref() else {
        return negative("response_body_identity_unavailable");
    };
    let content_type = headers
        .content_type
        .as_deref()
        .ok_or_else(|| "captured response content type is missing".to_string())?;
    let content_digest_value = headers
        .content_digest
        .as_deref()
        .ok_or_else(|| "captured response content digest is missing".to_string())?;
    let signature_input_value = headers
        .signature_input
        .as_deref()
        .ok_or_else(|| "captured response signature input is missing".to_string())?;
    let signature_value = headers
        .signature
        .as_deref()
        .ok_or_else(|| "captured response signature is missing".to_string())?;
    if content_type != "application/json" {
        return negative("response_content_type_not_profiled");
    }
    let digest = match parse_content_digest(content_digest_value) {
        Ok(digest) => digest,
        Err(_) => return negative("response_content_digest_invalid"),
    };
    if hex::encode(digest) != response_sha256 {
        return negative("response_content_digest_mismatch");
    }
    let (created_at_unix, expires_at_unix, key_id) =
        match parse_signature_input(signature_input_value, receipt.operation) {
            Ok(value) => value,
            Err(_) => return negative("response_signature_input_invalid"),
        };
    let signature_bytes = match parse_signature_value(signature_value) {
        Ok(value) => value,
        Err(_) => return negative("response_signature_value_invalid"),
    };
    let trusted = match trusted_response_key(policy, &key_id) {
        Ok(trusted) => trusted,
        Err(_) => return negative("response_signer_not_trusted"),
    };
    if validate_trusted_response_key_binding(trusted, intent).is_err() {
        return negative("response_signer_binding_mismatch");
    }
    let base = match signature_base(
        intent,
        receipt.operation,
        receipt.reconciliation_id.as_deref(),
        &receipt.endpoint,
        receipt.http_status.unwrap_or(0),
        content_digest_value,
        signature_input_value,
    ) {
        Ok(base) => base,
        Err(_) => return negative("response_signature_context_invalid"),
    };
    let public_key = decode_hex_array::<32>(
        &trusted.public_key,
        "trusted factory adapter response public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid factory adapter response public key: {error}"))?;
    if verifying_key
        .verify_strict(base.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .is_err()
    {
        return negative("response_signature_invalid");
    }
    if validate_signature_window(
        created_at_unix,
        expires_at_unix,
        response_policy(policy)?,
        Some(evaluated_at_unix),
    )
    .is_err()
    {
        return negative("response_signature_time_inactive");
    }

    let evidence = FactoryReleaseAdapterHttpMessageSignature {
        profile: FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE.into(),
        label: FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL.into(),
        algorithm: FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.clone(),
        created_at_unix,
        expires_at_unix,
        content_digest: content_digest_value.into(),
        signature_input: signature_input_value.into(),
        signature: signature_value.into(),
    };
    let signer = FactoryReleaseAdapterResponseSigner {
        key_id,
        factory_id: trusted.factory_id.clone(),
        provider: receipt.provider,
        public_key: trusted.public_key.clone(),
    };
    build_authentication_report(
        intent_sha256,
        &receipt_sha256,
        receipt,
        policy_evidence,
        Some(signer),
        Some(evidence),
        evaluated_at_unix,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_authentication_report(
    intent_sha256: &str,
    receipt_sha256: &str,
    receipt: &SignedFactoryReleaseAdapterReceipt,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    signer: Option<FactoryReleaseAdapterResponseSigner>,
    response_signature: Option<FactoryReleaseAdapterHttpMessageSignature>,
    evaluated_at_unix: u64,
    failure: Option<&str>,
) -> Result<FactoryReleaseAdapterResponseAuthenticationReport, String> {
    let authenticated = failure.is_none();
    let mut report = FactoryReleaseAdapterResponseAuthenticationReport {
        schema_version: FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCHEMA_VERSION,
        authentication_scope: FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCOPE.into(),
        status: if authenticated {
            "response_authenticated"
        } else {
            "not_authenticated"
        }
        .into(),
        response_authenticated: authenticated,
        response_signature_verified: authenticated,
        response_content_digest_verified: authenticated,
        policy_pack_pin_matched: true,
        signer_policy_matched: authenticated,
        signature_time_active: authenticated,
        acknowledgement_authenticated: authenticated && receipt.acknowledgement_validated,
        accepted: authenticated && receipt.accepted,
        raw_response_authenticity_verified: authenticated,
        endpoint_transport_authenticity_verified: false,
        factory_legal_identity_verified: false,
        trusted_time_verified: false,
        server_side_idempotency_enforced: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        intent_sha256: intent_sha256.into(),
        adapter_receipt_sha256: receipt_sha256.into(),
        policy_pack: policy_evidence.clone(),
        signer,
        response_signature,
        evaluated_at_unix,
        authentication_failure: failure.map(str::to_owned),
        adapter_receipt: receipt.clone(),
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    Ok(report)
}

fn validate_factory_release_adapter_response_authentication_report(
    report: &FactoryReleaseAdapterResponseAuthenticationReport,
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy: &OrganizationPolicyPack,
    policy_source: &[u8],
) -> Result<(), String> {
    if report.schema_version != FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCHEMA_VERSION
        || report.authentication_scope != FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCOPE
        || !report.policy_pack_pin_matched
        || report.endpoint_transport_authenticity_verified
        || report.factory_legal_identity_verified
        || report.trusted_time_verified
        || report.server_side_idempotency_enforced
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
    {
        return Err(
            "factory adapter response authentication identity or nonclaims are invalid".into(),
        );
    }
    validate_timestamp(
        report.evaluated_at_unix,
        "adapter response evaluation timestamp",
    )?;
    validate_digest(&report.intent_sha256, "factory release intent SHA-256")?;
    validate_digest(
        &report.adapter_receipt_sha256,
        "factory release adapter receipt SHA-256",
    )?;
    validate_digest(
        &report.binding_sha256,
        "factory adapter response report binding SHA-256",
    )?;
    let intent_source = render_signed_factory_release_submission_intent(intent)?;
    if sha256(&intent_source) != report.intent_sha256 {
        return Err("authenticated response report does not bind the exact intent".into());
    }
    let receipt_source = render_signed_factory_release_adapter_receipt(&report.adapter_receipt)?;
    parse_signed_factory_release_adapter_receipt(&receipt_source, intent)?;
    if sha256(&receipt_source) != report.adapter_receipt_sha256 {
        return Err("authenticated response report does not bind the exact adapter receipt".into());
    }
    validate_policy_evidence(&report.policy_pack, policy, policy_source)?;

    let authenticated = report.response_authenticated;
    if report.status
        != if authenticated {
            "response_authenticated"
        } else {
            "not_authenticated"
        }
        || report.response_signature_verified != authenticated
        || report.response_content_digest_verified != authenticated
        || report.signer_policy_matched != authenticated
        || report.signature_time_active != authenticated
        || report.raw_response_authenticity_verified != authenticated
        || report.acknowledgement_authenticated
            != (authenticated && report.adapter_receipt.acknowledgement_validated)
        || report.accepted != (authenticated && report.adapter_receipt.accepted)
        || report.signer.is_some() != authenticated
        || report.response_signature.is_some() != authenticated
        || report.authentication_failure.is_some() == authenticated
    {
        return Err("factory adapter response authentication flags are invalid".into());
    }
    if authenticated {
        verify_positive_report(report, intent, policy)?;
    } else {
        let failure = report.authentication_failure.as_deref().ok_or_else(|| {
            "unauthenticated factory adapter response has no failure code".to_string()
        })?;
        if !matches!(
            failure,
            "transport_error"
                | "response_signature_headers_missing"
                | "response_signature_headers_duplicated"
                | "response_signature_headers_invalid"
                | "credential_reflection_detected"
                | "response_body_identity_unavailable"
                | "response_content_type_not_profiled"
                | "response_content_digest_invalid"
                | "response_content_digest_mismatch"
                | "response_signature_input_invalid"
                | "response_signature_value_invalid"
                | "response_signer_not_trusted"
                | "response_signer_binding_mismatch"
                | "response_signature_context_invalid"
                | "response_signature_invalid"
                | "response_signature_time_inactive"
        ) {
            return Err("factory adapter response authentication failure code is invalid".into());
        }
    }
    if report.binding_sha256 != report_binding(report)? {
        return Err("factory adapter response authentication binding is invalid".into());
    }
    Ok(())
}

fn verify_positive_report(
    report: &FactoryReleaseAdapterResponseAuthenticationReport,
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy: &OrganizationPolicyPack,
) -> Result<(), String> {
    let signer = report.signer.as_ref().expect("authenticated signer exists");
    let evidence = report
        .response_signature
        .as_ref()
        .expect("authenticated signature exists");
    validate_signature_evidence_shape(evidence, report.adapter_receipt.operation)?;
    let trusted = trusted_response_key(policy, &evidence.key_id)?;
    validate_trusted_response_key_binding(trusted, intent)?;
    if signer.key_id != trusted.key_id
        || signer.factory_id != trusted.factory_id
        || signer.provider != report.adapter_receipt.provider
        || signer.public_key != trusted.public_key
    {
        return Err("authenticated response signer does not match its pinned policy key".into());
    }
    let response_sha256 = report
        .adapter_receipt
        .response_sha256
        .as_deref()
        .ok_or_else(|| "authenticated response has no response body identity".to_string())?;
    if hex::encode(parse_content_digest(&evidence.content_digest)?) != response_sha256 {
        return Err("authenticated response Content-Digest does not match its body".into());
    }
    validate_signature_window(
        evidence.created_at_unix,
        evidence.expires_at_unix,
        response_policy(policy)?,
        Some(report.evaluated_at_unix),
    )?;
    let base = signature_base(
        intent,
        report.adapter_receipt.operation,
        report.adapter_receipt.reconciliation_id.as_deref(),
        &report.adapter_receipt.endpoint,
        report.adapter_receipt.http_status.ok_or_else(|| {
            "authenticated factory adapter response has no HTTP status".to_string()
        })?,
        &evidence.content_digest,
        &evidence.signature_input,
    )?;
    let public_key = decode_hex_array::<32>(
        &trusted.public_key,
        "trusted factory adapter response public key",
    )?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|error| format!("invalid factory adapter response public key: {error}"))?;
    verifying_key
        .verify_strict(
            base.as_bytes(),
            &Signature::from_bytes(&parse_signature_value(&evidence.signature)?),
        )
        .map_err(|error| format!("invalid factory adapter response signature: {error}"))
}

fn capture_response_headers(
    response: &ureq::http::Response<ureq::Body>,
    bearer_token: &str,
) -> CapturedResponseHeaders {
    let mut captured = CapturedResponseHeaders::default();
    let mut values = Vec::new();
    for name in [
        "content-type",
        "content-digest",
        "signature-input",
        "signature",
    ] {
        match singleton_header(response, name) {
            Ok(value) => values.push((name, value)),
            Err(failure) => {
                captured.failure = Some(failure);
                return captured;
            }
        }
    }
    if values.iter().any(|(_, value)| {
        value
            .as_bytes()
            .windows(bearer_token.len())
            .any(|window| window == bearer_token.as_bytes())
    }) {
        captured.failure = Some("credential_reflection_detected");
        return captured;
    }
    for (name, value) in values {
        match name {
            "content-type" => captured.content_type = Some(value),
            "content-digest" => captured.content_digest = Some(value),
            "signature-input" => captured.signature_input = Some(value),
            "signature" => captured.signature = Some(value),
            _ => unreachable!("fixed response signature header"),
        }
    }
    captured
}

fn singleton_header(
    response: &ureq::http::Response<ureq::Body>,
    name: &str,
) -> Result<String, &'static str> {
    let mut values = response.headers().get_all(name).iter();
    let Some(value) = values.next() else {
        return Err("response_signature_headers_missing");
    };
    if values.next().is_some() {
        return Err("response_signature_headers_duplicated");
    }
    let value = value
        .to_str()
        .map_err(|_| "response_signature_headers_invalid")?;
    if value.is_empty()
        || value.len() > 8 * 1024
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return Err("response_signature_headers_invalid");
    }
    Ok(value.into())
}

#[allow(clippy::too_many_arguments)]
fn validate_network_inputs(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    package: &[u8],
    bearer_token: &str,
    timeout_seconds: u64,
    endpoint: &str,
    allow_http_loopback: bool,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
) -> Result<(), String> {
    let intent_source = render_signed_factory_release_submission_intent(intent)?;
    validate_digest(intent_sha256, "factory release submission intent SHA-256")?;
    if sha256(&intent_source) != intent_sha256 {
        return Err("factory release submission intent SHA-256 does not match its bytes".into());
    }
    if !package.is_empty()
        && (package.len() as u64 != intent.manufacturing_package.bytes
            || sha256(package) != intent.manufacturing_package.sha256)
    {
        return Err("manufacturing package does not match the durable submission intent".into());
    }
    validate_bearer_token(bearer_token)?;
    if !(1..=600).contains(&timeout_seconds) {
        return Err("factory release timeout must be between 1 and 600 seconds".into());
    }
    validate_endpoint(endpoint, allow_http_loopback)?;
    if endpoint.chars().count() > MAX_ENDPOINT_CHARS {
        return Err(format!(
            "factory release endpoint exceeds {MAX_ENDPOINT_CHARS} characters"
        ));
    }
    validate_policy_evidence_without_source(policy_evidence, policy)?;
    if !response_policy(policy)?.trusted_keys.iter().any(|trusted| {
        trusted.factory_id == intent.factory_id
            && trusted.provider == provider_name(intent.provider)
    }) {
        return Err(
            "adapter response policy has no key for the selected factory and provider".into(),
        );
    }
    Ok(())
}

fn validate_signature_context(
    intent: &SignedFactoryReleaseSubmissionIntent,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
) -> Result<(), String> {
    render_signed_factory_release_submission_intent(intent)?;
    validate_endpoint(endpoint, true)?;
    if endpoint.chars().count() > MAX_ENDPOINT_CHARS {
        return Err("factory release signature endpoint exceeds its bound".into());
    }
    match (operation, reconciliation_id) {
        (FactoryReleaseAdapterOperation::Submit, None) => {
            if endpoint != intent.submission_endpoint {
                return Err("submit response signature endpoint does not match the intent".into());
            }
        }
        (FactoryReleaseAdapterOperation::Reconcile, Some(reconciliation_id)) => {
            validate_digest(reconciliation_id, "factory release reconciliation id")?;
        }
        _ => return Err("factory release response signature operation shape is invalid".into()),
    }
    Ok(())
}

fn signature_components(operation: FactoryReleaseAdapterOperation) -> &'static str {
    match operation {
        FactoryReleaseAdapterOperation::Submit => {
            "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
        }
        FactoryReleaseAdapterOperation::Reconcile => {
            "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-reconciliation-id\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
        }
    }
}

fn signature_input(
    operation: FactoryReleaseAdapterOperation,
    created_at_unix: u64,
    expires_at_unix: u64,
    key_id: &str,
) -> String {
    format!(
        "{}={};created={created_at_unix};expires={expires_at_unix};keyid=\"{key_id}\";alg=\"{}\";tag=\"{}\"",
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL,
        signature_components(operation),
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM,
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE,
    )
}

fn parse_signature_input(
    value: &str,
    operation: FactoryReleaseAdapterOperation,
) -> Result<(u64, u64, String), String> {
    let prefix = format!(
        "{}={};created=",
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL,
        signature_components(operation)
    );
    let rest = value
        .strip_prefix(&prefix)
        .ok_or_else(|| "factory adapter response Signature-Input profile is invalid".to_string())?;
    let (created, rest) = rest
        .split_once(";expires=")
        .ok_or_else(|| "factory adapter response Signature-Input has no expires".to_string())?;
    let (expires, rest) = rest
        .split_once(";keyid=\"")
        .ok_or_else(|| "factory adapter response Signature-Input has no keyid".to_string())?;
    let suffix = format!(
        "\";alg=\"{}\";tag=\"{}\"",
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM,
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE
    );
    let key_id = rest
        .strip_suffix(&suffix)
        .ok_or_else(|| "factory adapter response Signature-Input suffix is invalid".to_string())?;
    validate_slug(key_id, "factory adapter response key id")?;
    let created = parse_structured_timestamp(created, "signature created")?;
    let expires = parse_structured_timestamp(expires, "signature expires")?;
    if value != signature_input(operation, created, expires, key_id) {
        return Err("factory adapter response Signature-Input is not canonical".into());
    }
    Ok((created, expires, key_id.into()))
}

#[allow(clippy::too_many_arguments)]
fn signature_base(
    intent: &SignedFactoryReleaseSubmissionIntent,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
    http_status: u16,
    content_digest: &str,
    signature_input: &str,
) -> Result<String, String> {
    validate_signature_context(intent, operation, reconciliation_id, endpoint)?;
    if !(100..=599).contains(&http_status) {
        return Err("factory adapter response HTTP status is outside its bound".into());
    }
    parse_content_digest(content_digest)?;
    let (created, expires, key_id) = parse_signature_input(signature_input, operation)?;
    let parameters = signature_input
        .strip_prefix(&format!(
            "{}=",
            FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL
        ))
        .ok_or_else(|| "factory adapter response Signature-Input label is invalid".to_string())?;
    if parameters != signature_input_for_parameters(operation, created, expires, &key_id) {
        return Err("factory adapter response signature parameters are invalid".into());
    }
    let method = match operation {
        FactoryReleaseAdapterOperation::Submit => "POST",
        FactoryReleaseAdapterOperation::Reconcile => "GET",
    };
    let mut lines = vec![
        format!("\"@status\": {http_status}"),
        format!("\"content-digest\": {content_digest}"),
        "\"content-type\": application/json".into(),
        "\"x-pcbex-adapter\";req: signed-factory-release-http-v1".into(),
        "\"x-pcbex-schema-version\";req: 1".into(),
        format!(
            "\"x-pcbex-response-signature-profile\";req: {}",
            FACTORY_RELEASE_ADAPTER_RESPONSE_PROFILE_HEADER
        ),
        format!("\"idempotency-key\";req: {}", intent.idempotency_key),
        format!("\"x-pcbex-request-nonce\";req: {}", intent.request_nonce),
    ];
    if let Some(reconciliation_id) = reconciliation_id {
        lines.push(format!(
            "\"x-pcbex-reconciliation-id\";req: {reconciliation_id}"
        ));
    }
    lines.extend([
        format!(
            "\"x-pcbex-release-subject-sha256\";req: {}",
            intent.release_subject_sha256
        ),
        format!(
            "\"x-pcbex-package-sha256\";req: {}",
            intent.manufacturing_package.sha256
        ),
        format!("\"x-pcbex-factory-id\";req: {}", intent.factory_id),
        format!("\"@method\";req: {method}"),
        format!("\"@target-uri\";req: {endpoint}"),
        format!("\"@signature-params\": {parameters}"),
    ]);
    let base = lines.join("\n");
    if !base.is_ascii() || base.contains('\r') || base.as_bytes().contains(&0) {
        return Err("factory adapter response signature base is invalid".into());
    }
    Ok(base)
}

fn signature_input_for_parameters(
    operation: FactoryReleaseAdapterOperation,
    created_at_unix: u64,
    expires_at_unix: u64,
    key_id: &str,
) -> String {
    signature_input(operation, created_at_unix, expires_at_unix, key_id)
        .strip_prefix(&format!(
            "{}=",
            FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL
        ))
        .expect("fixed signature label")
        .into()
}

#[cfg(test)]
fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

fn parse_content_digest(value: &str) -> Result<[u8; 32], String> {
    let encoded = value
        .strip_prefix("sha-256=:")
        .and_then(|value| value.strip_suffix(':'))
        .ok_or_else(|| "factory adapter response Content-Digest profile is invalid".to_string())?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid factory adapter response Content-Digest: {error}"))?;
    let digest: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "factory adapter response Content-Digest is not SHA-256".to_string())?;
    if content_digest_from_digest(&digest) != value {
        return Err("factory adapter response Content-Digest is not canonical".into());
    }
    Ok(digest)
}

fn content_digest_from_digest(digest: &[u8; 32]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(digest))
}

fn parse_signature_value(value: &str) -> Result<[u8; 64], String> {
    let prefix = format!("{}=:", FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL);
    let encoded = value
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(':'))
        .ok_or_else(|| "factory adapter response Signature field is invalid".to_string())?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid factory adapter response Signature: {error}"))?;
    let signature: [u8; 64] = decoded
        .try_into()
        .map_err(|_| "factory adapter response Signature is not Ed25519".to_string())?;
    let canonical = format!(
        "{}=:{}:",
        FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL,
        STANDARD.encode(signature)
    );
    if canonical != value {
        return Err("factory adapter response Signature is not canonical".into());
    }
    Ok(signature)
}

fn parse_structured_timestamp(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty()
        || value.len() > 15
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(format!("factory adapter response {label} is invalid"));
    }
    let timestamp = value
        .parse::<u64>()
        .map_err(|error| format!("invalid factory adapter response {label}: {error}"))?;
    validate_timestamp(timestamp, label)?;
    Ok(timestamp)
}

fn validate_signature_window(
    created_at_unix: u64,
    expires_at_unix: u64,
    policy: &FactoryAdapterResponseAuthenticationPolicy,
    evaluated_at_unix: Option<u64>,
) -> Result<(), String> {
    validate_timestamp(created_at_unix, "signature created timestamp")?;
    validate_timestamp(expires_at_unix, "signature expires timestamp")?;
    let duration = expires_at_unix
        .checked_sub(created_at_unix)
        .filter(|duration| *duration > 0)
        .ok_or_else(|| "factory adapter response signature window is invalid".to_string())?;
    if duration > policy.maximum_validity_seconds {
        return Err("factory adapter response signature exceeds policy validity".into());
    }
    if let Some(evaluated_at_unix) = evaluated_at_unix {
        validate_timestamp(evaluated_at_unix, "signature evaluation timestamp")?;
        if evaluated_at_unix < created_at_unix || evaluated_at_unix > expires_at_unix {
            return Err("factory adapter response signature is outside its active window".into());
        }
    }
    Ok(())
}

fn validate_signature_evidence_shape(
    evidence: &FactoryReleaseAdapterHttpMessageSignature,
    operation: FactoryReleaseAdapterOperation,
) -> Result<(), String> {
    if evidence.profile != FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE
        || evidence.label != FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL
        || evidence.algorithm != FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM
    {
        return Err("factory adapter response signature profile is invalid".into());
    }
    validate_slug(&evidence.key_id, "factory adapter response key id")?;
    parse_content_digest(&evidence.content_digest)?;
    let (created, expires, key_id) = parse_signature_input(&evidence.signature_input, operation)?;
    if created != evidence.created_at_unix
        || expires != evidence.expires_at_unix
        || key_id != evidence.key_id
    {
        return Err("factory adapter response signature metadata is inconsistent".into());
    }
    parse_signature_value(&evidence.signature)?;
    Ok(())
}

fn response_policy(
    policy: &OrganizationPolicyPack,
) -> Result<&FactoryAdapterResponseAuthenticationPolicy, String> {
    policy
        .factory_adapter_response_authentication_policy
        .as_ref()
        .ok_or_else(|| {
            "organization policy pack has no factory adapter response authentication policy"
                .to_string()
        })
}

fn trusted_response_key<'a>(
    policy: &'a OrganizationPolicyPack,
    key_id: &str,
) -> Result<&'a TrustedFactoryAdapterResponseKey, String> {
    validate_policy_pack(policy)?;
    validate_slug(key_id, "factory adapter response key id")?;
    response_policy(policy)?
        .trusted_keys
        .iter()
        .find(|trusted| trusted.key_id == key_id)
        .ok_or_else(|| "factory adapter response key is not trusted by policy".to_string())
}

fn validate_trusted_response_key_binding(
    trusted: &TrustedFactoryAdapterResponseKey,
    intent: &SignedFactoryReleaseSubmissionIntent,
) -> Result<(), String> {
    if trusted.factory_id != intent.factory_id || trusted.provider != provider_name(intent.provider)
    {
        return Err(
            "factory adapter response key does not match the intent factory and provider".into(),
        );
    }
    Ok(())
}

fn validate_policy_evidence_without_source(
    evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
) -> Result<(), String> {
    validate_policy_pack(policy)?;
    validate_artifact_identity(
        &evidence.source,
        MAX_POLICY_PACK_BYTES,
        "organization policy pack",
    )?;
    validate_digest(
        &evidence.canonical_sha256,
        "canonical adapter response policy SHA-256",
    )?;
    validate_slug(&evidence.id, "adapter response policy id")?;
    if evidence.revision == 0
        || evidence.id != policy.id
        || evidence.revision != policy.revision
        || evidence.canonical_sha256 != policy_pack_sha256(policy)?
        || policy
            .factory_adapter_response_authentication_policy
            .is_none()
    {
        return Err("factory adapter response policy evidence does not match its policy".into());
    }
    Ok(())
}

fn validate_policy_evidence(
    evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
    policy_source: &[u8],
) -> Result<(), String> {
    validate_policy_evidence_without_source(evidence, policy)?;
    if evidence.source != exact_identity(policy_source) {
        return Err("factory adapter response policy source identity does not match".into());
    }
    Ok(())
}

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    maximum_bytes: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum_bytes {
        return Err(format!("{label} byte count is outside its bound"));
    }
    validate_digest(&identity.sha256, &format!("{label} SHA-256"))
}

fn report_binding(
    report: &FactoryReleaseAdapterResponseAuthenticationReport,
) -> Result<String, String> {
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &ReportBinding {
            schema_version: report.schema_version,
            authentication_scope: &report.authentication_scope,
            status: &report.status,
            response_authenticated: report.response_authenticated,
            response_signature_verified: report.response_signature_verified,
            response_content_digest_verified: report.response_content_digest_verified,
            policy_pack_pin_matched: report.policy_pack_pin_matched,
            signer_policy_matched: report.signer_policy_matched,
            signature_time_active: report.signature_time_active,
            acknowledgement_authenticated: report.acknowledgement_authenticated,
            accepted: report.accepted,
            raw_response_authenticity_verified: report.raw_response_authenticity_verified,
            endpoint_transport_authenticity_verified: report
                .endpoint_transport_authenticity_verified,
            factory_legal_identity_verified: report.factory_legal_identity_verified,
            trusted_time_verified: report.trusted_time_verified,
            server_side_idempotency_enforced: report.server_side_idempotency_enforced,
            capacity_reserved: report.capacity_reserved,
            order_placed: report.order_placed,
            payment_performed: report.payment_performed,
            exactly_once_execution_verified: report.exactly_once_execution_verified,
            intent_sha256: &report.intent_sha256,
            adapter_receipt_sha256: &report.adapter_receipt_sha256,
            policy_pack: &report.policy_pack,
            signer: &report.signer,
            response_signature: &report.response_signature,
            evaluated_at_unix: report.evaluated_at_unix,
            authentication_failure: &report.authentication_failure,
            adapter_receipt: &report.adapter_receipt,
        },
    )
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> Result<String, String> {
    let source = serde_json::to_vec(value)
        .map_err(|error| format!("serializing factory adapter response binding: {error}"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(source);
    Ok(hex::encode(hash.finalize()))
}

fn render_bounded(value: &impl Serialize, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut source =
        serde_json::to_vec_pretty(value).map_err(|error| format!("rendering {label}: {error}"))?;
    source.push(b'\n');
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    Ok(source)
}

fn parse_canonical<T: for<'de> Deserialize<'de> + Serialize>(
    source: &[u8],
    maximum: u64,
    label: &str,
) -> Result<T, String> {
    if source.is_empty() || source.len() as u64 > maximum {
        return Err(format!("{label} must contain 1 to {maximum} bytes"));
    }
    reject_duplicate_json_keys(source)
        .map_err(|error| format!("invalid {label} JSON: {error:#}"))?;
    let value: T =
        serde_json::from_slice(source).map_err(|error| format!("invalid {label} JSON: {error}"))?;
    if render_bounded(&value, maximum, label)? != source {
        return Err(format!("{label} is not canonical pretty JSON"));
    }
    Ok(value)
}

fn exact_identity(source: &[u8]) -> ExactArtifactIdentity {
    ExactArtifactIdentity {
        bytes: source.len() as u64,
        sha256: sha256(source),
    }
}

fn sha256(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

fn validate_timestamp(value: u64, label: &str) -> Result<(), String> {
    if value > MAX_SIGNATURE_TIMESTAMP {
        return Err(format!(
            "factory adapter response {label} is outside its bound"
        ));
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

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
    {
        return Err(format!("{label} is invalid"));
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
            "{label} must contain {} lowercase hex digits",
            N * 2
        ));
    }
    let decoded = hex::decode(value).map_err(|error| format!("decoding {label}: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} has an invalid length"))
}

fn provider_name(provider: FactoryProvider) -> &'static str {
    match provider {
        FactoryProvider::Jlcpcb => "jlcpcb",
        FactoryProvider::Pcbway => "pcbway",
        FactoryProvider::Generic => "generic",
    }
}

pub(crate) fn factory_release_adapter_http_message_signature_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-adapter-http-message-signature-v1.json",
        "title": "pcbex RFC 9421 factory release adapter response signature",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "profile", "label", "algorithm", "key_id", "created_at_unix",
            "expires_at_unix", "content_digest", "signature_input", "signature"
        ],
        "properties": {
            "profile": {"const": FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_PROFILE},
            "label": {"const": FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_LABEL},
            "algorithm": {"const": FACTORY_RELEASE_ADAPTER_RESPONSE_SIGNATURE_ALGORITHM},
            "key_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "created_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_SIGNATURE_TIMESTAMP},
            "expires_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_SIGNATURE_TIMESTAMP},
            "content_digest": {"type": "string", "pattern": "^sha-256=:[A-Za-z0-9+/]{43}=:$", "maxLength": 60},
            "signature_input": {"type": "string", "minLength": 1, "maxLength": 8192},
            "signature": {"type": "string", "pattern": "^pcbex=:[A-Za-z0-9+/]{86}==:$", "maxLength": 100}
        }
    })
}

pub(crate) fn factory_release_adapter_response_authentication_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let false_value = json!({"const": false});
    let signature_schema = factory_release_adapter_http_message_signature_json_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-adapter-response-authentication-report-v1.json",
        "title": "pcbex policy-pinned factory release adapter response authentication report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "authentication_scope", "status",
            "response_authenticated", "response_signature_verified",
            "response_content_digest_verified", "policy_pack_pin_matched",
            "signer_policy_matched", "signature_time_active",
            "acknowledgement_authenticated", "accepted",
            "raw_response_authenticity_verified",
            "endpoint_transport_authenticity_verified",
            "factory_legal_identity_verified", "trusted_time_verified",
            "server_side_idempotency_enforced", "capacity_reserved", "order_placed",
            "payment_performed", "exactly_once_execution_verified", "intent_sha256",
            "adapter_receipt_sha256", "policy_pack", "signer", "response_signature",
            "evaluated_at_unix", "authentication_failure", "adapter_receipt",
            "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCHEMA_VERSION},
            "authentication_scope": {"const": FACTORY_RELEASE_ADAPTER_RESPONSE_AUTHENTICATION_SCOPE},
            "status": {"enum": ["response_authenticated", "not_authenticated"]},
            "response_authenticated": {"type": "boolean"},
            "response_signature_verified": {"type": "boolean"},
            "response_content_digest_verified": {"type": "boolean"},
            "policy_pack_pin_matched": {"const": true},
            "signer_policy_matched": {"type": "boolean"},
            "signature_time_active": {"type": "boolean"},
            "acknowledgement_authenticated": {"type": "boolean"},
            "accepted": {"type": "boolean"},
            "raw_response_authenticity_verified": {"type": "boolean"},
            "endpoint_transport_authenticity_verified": false_value,
            "factory_legal_identity_verified": false_value,
            "trusted_time_verified": false_value,
            "server_side_idempotency_enforced": false_value,
            "capacity_reserved": false_value,
            "order_placed": false_value,
            "payment_performed": false_value,
            "exactly_once_execution_verified": false_value,
            "intent_sha256": digest,
            "adapter_receipt_sha256": digest,
            "policy_pack": {
                "type": "object", "additionalProperties": false,
                "required": ["source", "canonical_sha256", "id", "revision"],
                "properties": {
                    "source": {
                        "type": "object", "additionalProperties": false,
                        "required": ["bytes", "sha256"],
                        "properties": {
                            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_POLICY_PACK_BYTES},
                            "sha256": digest
                        }
                    },
                    "canonical_sha256": digest,
                    "id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                    "revision": {"type": "integer", "minimum": 1, "maximum": 4294967295_u64}
                }
            },
            "signer": {"oneOf": [
                {"type": "null"},
                {
                    "type": "object", "additionalProperties": false,
                    "required": ["key_id", "factory_id", "provider", "public_key"],
                    "properties": {
                        "key_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "factory_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
                        "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
                        "public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                    }
                }
            ]},
            "response_signature": {"oneOf": [{"type": "null"}, signature_schema]},
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_SIGNATURE_TIMESTAMP},
            "authentication_failure": {"oneOf": [
                {"type": "null"},
                {"enum": [
                    "transport_error", "response_signature_headers_missing",
                    "response_signature_headers_duplicated", "response_signature_headers_invalid",
                    "credential_reflection_detected", "response_body_identity_unavailable",
                    "response_content_type_not_profiled", "response_content_digest_invalid",
                    "response_content_digest_mismatch", "response_signature_input_invalid",
                    "response_signature_value_invalid", "response_signer_not_trusted",
                    "response_signer_binding_mismatch", "response_signature_context_invalid",
                    "response_signature_invalid", "response_signature_time_inactive"
                ]}
            ]},
            "adapter_receipt": signed_factory_release_adapter_receipt_json_schema(),
            "binding_sha256": digest
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_pack::{
        FactoryAdapterResponseAuthenticationPolicy, TrustedFactoryAdapterResponseKey,
        parse_policy_pack,
    };
    use crate::signed_factory_receipt_release_submission::{
        FactoryReleaseAdapterAcknowledgement, FactoryReleaseAdapterStatus,
        SIGNED_FACTORY_RELEASE_ADAPTER_ACKNOWLEDGEMENT_SCOPE,
        SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION,
        test_signed_factory_release_submission_intent,
    };
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
    };

    const TOKEN: &str = "test-authenticated-factory-token-1483";
    const KEY_ID: &str = "factory-response-key-a";
    const SECRET_KEY: [u8; 32] = [37; 32];

    fn policy() -> (OrganizationPolicyPack, Vec<u8>, String) {
        let mut policy =
            parse_policy_pack(include_str!("../../../examples/acme-policy-pack.json")).unwrap();
        policy.factory_adapter_response_authentication_policy =
            Some(FactoryAdapterResponseAuthenticationPolicy {
                maximum_validity_seconds: 300,
                trusted_keys: vec![TrustedFactoryAdapterResponseKey {
                    key_id: KEY_ID.into(),
                    factory_id: "factory-a".into(),
                    provider: "generic".into(),
                    public_key: hex::encode(
                        SigningKey::from_bytes(&SECRET_KEY)
                            .verifying_key()
                            .to_bytes(),
                    ),
                }],
            });
        validate_policy_pack(&policy).unwrap();
        let digest = policy_pack_sha256(&policy).unwrap();
        let mut source = serde_json::to_vec_pretty(&policy).unwrap();
        source.push(b'\n');
        (policy, source, digest)
    }

    fn acknowledgement(
        intent: &SignedFactoryReleaseSubmissionIntent,
        operation: FactoryReleaseAdapterOperation,
        reconciliation_id: Option<&str>,
    ) -> Vec<u8> {
        serde_json::to_vec(&FactoryReleaseAdapterAcknowledgement {
            schema_version: SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION,
            acknowledgement_scope: SIGNED_FACTORY_RELEASE_ADAPTER_ACKNOWLEDGEMENT_SCOPE.into(),
            operation,
            idempotency_key: intent.idempotency_key.clone(),
            request_nonce: intent.request_nonce.clone(),
            reconciliation_id: reconciliation_id.map(str::to_owned),
            release_subject_sha256: intent.release_subject_sha256.clone(),
            manufacturing_package_sha256: intent.manufacturing_package.sha256.clone(),
            factory_id: intent.factory_id.clone(),
            provider: intent.provider,
            status: FactoryReleaseAdapterStatus::AdapterAccepted,
            submission_id: "submission-1483".into(),
        })
        .unwrap()
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
            if let Some(offset) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break offset + 4;
            }
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0);
            request.extend_from_slice(&buffer[..read]);
        }
        request
    }

    fn serve_once(
        listener: TcpListener,
        status: u16,
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let reason = if status == 200 { "OK" } else { "Created" };
            let mut response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            request
        })
    }

    fn signed_headers(
        intent: &SignedFactoryReleaseSubmissionIntent,
        body: &[u8],
        policy: &OrganizationPolicyPack,
        status: u16,
        created: u64,
        expires: u64,
    ) -> FactoryReleaseAdapterHttpMessageSignature {
        sign_factory_release_adapter_http_response(
            intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            &intent.submission_endpoint,
            status,
            body,
            policy,
            KEY_ID,
            &SECRET_KEY,
            created,
            expires,
        )
        .unwrap()
    }

    fn header_lines(
        signature: &FactoryReleaseAdapterHttpMessageSignature,
    ) -> Vec<(String, String)> {
        vec![
            ("Content-Digest".into(), signature.content_digest.clone()),
            ("Signature-Input".into(), signature.signature_input.clone()),
            ("Signature".into(), signature.signature.clone()),
        ]
    }

    fn assert_recursively_closed(value: &Value) {
        match value {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".into())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false))
                    );
                }
                object.values().for_each(assert_recursively_closed);
            }
            Value::Array(values) => values.iter().for_each(assert_recursively_closed),
            _ => {}
        }
    }

    #[test]
    fn signature_profile_has_stable_golden_bytes() {
        let (policy, _, _) = policy();
        let endpoint = "http://127.0.0.1:14830/release";
        let package = b"manufacturing-package-1483";
        let intent = test_signed_factory_release_submission_intent(endpoint, package);
        let body = acknowledgement(&intent, FactoryReleaseAdapterOperation::Submit, None);
        let signature = signed_headers(&intent, &body, &policy, 200, 1_700_000_000, 1_700_000_120);
        assert_eq!(
            signature.content_digest,
            "sha-256=:absLA17/VT3e0lGWu5d94LjLP8DoTHRWrOlu3z1+nno=:"
        );
        assert_eq!(
            signature.signature_input,
            "pcbex=(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req);created=1700000000;expires=1700000120;keyid=\"factory-response-key-a\";alg=\"ed25519\";tag=\"pcbex-signed-factory-release-response-v1\""
        );
        assert_eq!(
            signature.signature,
            "pcbex=:zAPPLa0vZsAcgtnajcrzd8wThf+Rq6G/W8Z/EAuKYqZFcA6j9uLHLYDLiIPPgMERFR7eT/O5tVBJIsxktkkuDA==:"
        );
    }

    #[test]
    fn authenticates_and_round_trips_a_policy_pinned_response() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
        let package = b"manufacturing-package-1483";
        let intent = test_signed_factory_release_submission_intent(&endpoint, package);
        let intent_source = render_signed_factory_release_submission_intent(&intent).unwrap();
        let intent_sha256 = sha256(&intent_source);
        let (policy, policy_source, policy_sha256) = policy();
        let (policy_evidence, parsed_policy) =
            capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                .unwrap();
        assert_eq!(policy, parsed_policy);
        let body = acknowledgement(&intent, FactoryReleaseAdapterOperation::Submit, None);
        let now = crate::current_unix_seconds().unwrap();
        let signature = signed_headers(&intent, &body, &policy, 200, now, now + 120);
        let server = serve_once(listener, 200, body, header_lines(&signature));

        let (receipt, report) = submit_authenticated_factory_release_adapter(
            &intent,
            &intent_sha256,
            package,
            TOKEN,
            5,
            true,
            now,
            &policy_evidence,
            &policy,
        )
        .unwrap();
        let request = String::from_utf8_lossy(&server.join().unwrap()).to_ascii_lowercase();
        assert!(request.starts_with("post /release http/1.1"));
        assert!(
            request
                .contains("x-pcbex-response-signature-profile: rfc9421-ed25519-content-digest-v1")
        );
        assert!(report.response_authenticated);
        assert!(report.response_signature_verified);
        assert!(report.response_content_digest_verified);
        assert!(report.acknowledgement_authenticated);
        assert!(report.accepted);
        assert!(report.raw_response_authenticity_verified);
        assert!(!receipt.raw_response_authenticity_verified);
        assert!(!report.endpoint_transport_authenticity_verified);
        assert!(!report.factory_legal_identity_verified);
        assert!(!report.trusted_time_verified);
        assert!(!report.capacity_reserved);
        assert!(!report.order_placed);
        assert!(!report.payment_performed);
        assert!(!report.exactly_once_execution_verified);
        let rendered = render_factory_release_adapter_response_authentication_report(
            &report,
            &intent,
            &policy_source,
            &policy_sha256,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_adapter_response_authentication_report(
                &rendered,
                &intent,
                &policy_source,
                &policy_sha256,
            )
            .unwrap(),
            report
        );
    }

    #[test]
    fn retains_closed_negative_evidence_for_body_status_and_time_failures() {
        for failure in ["body", "status", "time"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
            let package = b"manufacturing-package-1483";
            let intent = test_signed_factory_release_submission_intent(&endpoint, package);
            let intent_source = render_signed_factory_release_submission_intent(&intent).unwrap();
            let intent_sha256 = sha256(&intent_source);
            let (policy, policy_source, policy_sha256) = policy();
            let (policy_evidence, _) =
                capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                    .unwrap();
            let body = acknowledgement(&intent, FactoryReleaseAdapterOperation::Submit, None);
            let now = crate::current_unix_seconds().unwrap();
            let (created, expires) = if failure == "time" {
                (now - 240, now - 120)
            } else {
                (now, now + 120)
            };
            let signed_status = 200;
            let signature =
                signed_headers(&intent, &body, &policy, signed_status, created, expires);
            let mut sent_body = body;
            let sent_status = if failure == "status" { 201 } else { 200 };
            if failure == "body" {
                sent_body.push(b'\n');
            }
            let server = serve_once(listener, sent_status, sent_body, header_lines(&signature));
            let (_, report) = submit_authenticated_factory_release_adapter(
                &intent,
                &intent_sha256,
                package,
                TOKEN,
                5,
                true,
                now,
                &policy_evidence,
                &policy,
            )
            .unwrap();
            server.join().unwrap();
            assert!(!report.response_authenticated);
            assert!(report.signer.is_none());
            assert!(report.response_signature.is_none());
            assert_eq!(
                report.authentication_failure.as_deref(),
                Some(match failure {
                    "body" => "response_content_digest_mismatch",
                    "status" => "response_signature_invalid",
                    "time" => "response_signature_time_inactive",
                    _ => unreachable!(),
                })
            );
            let rendered = render_factory_release_adapter_response_authentication_report(
                &report,
                &intent,
                &policy_source,
                &policy_sha256,
            )
            .unwrap();
            parse_factory_release_adapter_response_authentication_report(
                &rendered,
                &intent,
                &policy_source,
                &policy_sha256,
            )
            .unwrap();
        }
    }

    #[test]
    fn rejects_missing_duplicate_and_credential_reflecting_signature_headers() {
        for failure in ["missing", "duplicate", "credential"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
            let package = b"manufacturing-package-1483";
            let intent = test_signed_factory_release_submission_intent(&endpoint, package);
            let intent_source = render_signed_factory_release_submission_intent(&intent).unwrap();
            let intent_sha256 = sha256(&intent_source);
            let (policy, policy_source, policy_sha256) = policy();
            let (policy_evidence, _) =
                capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                    .unwrap();
            let body = acknowledgement(&intent, FactoryReleaseAdapterOperation::Submit, None);
            let now = crate::current_unix_seconds().unwrap();
            let signature = signed_headers(&intent, &body, &policy, 200, now, now + 120);
            let mut headers = if failure == "missing" {
                Vec::new()
            } else {
                header_lines(&signature)
            };
            if failure == "duplicate" {
                headers.push(("Signature".into(), signature.signature.clone()));
            } else if failure == "credential" {
                headers[0].1.push_str(TOKEN);
            }
            let server = serve_once(listener, 200, body, headers);
            let (_, report) = submit_authenticated_factory_release_adapter(
                &intent,
                &intent_sha256,
                package,
                TOKEN,
                5,
                true,
                now,
                &policy_evidence,
                &policy,
            )
            .unwrap();
            server.join().unwrap();
            assert!(!report.response_authenticated);
            assert_eq!(
                report.authentication_failure.as_deref(),
                Some(match failure {
                    "missing" => "response_signature_headers_missing",
                    "duplicate" => "response_signature_headers_duplicated",
                    "credential" => "credential_reflection_detected",
                    _ => unreachable!(),
                })
            );
        }
    }

    #[test]
    fn schemas_are_recursively_closed_and_keep_nonclaims_false() {
        let signature = factory_release_adapter_http_message_signature_json_schema();
        let report = factory_release_adapter_response_authentication_report_json_schema();
        assert_recursively_closed(&signature);
        assert_recursively_closed(&report);
        assert_eq!(
            report["properties"]["trusted_time_verified"]["const"],
            false
        );
        assert_eq!(report["properties"]["capacity_reserved"]["const"], false);
        assert_eq!(report["properties"]["order_placed"]["const"], false);
        assert_eq!(report["properties"]["payment_performed"]["const"], false);
    }
}
