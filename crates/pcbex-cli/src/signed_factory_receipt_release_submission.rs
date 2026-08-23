//! Durable, idempotency-keyed submission of one locally reserved signed release.
//!
//! This module deliberately separates a client-side durable intent from the
//! factory acknowledgement.  A committed intent is never used to retransmit
//! the manufacturing package.  Missing or uncertain results must be observed
//! through the reconciliation request instead.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory::{
    FactoryProvider, response_contains_bearer_token, validate_bearer_token, validate_endpoint,
    validate_env_name,
};
use crate::signed_factory_receipt_release_reservation::SignedFactoryReceiptReleaseReservation;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};

pub(crate) const SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION: u32 = 1;
pub(crate) const SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_SCOPE: &str =
    "durable-idempotency-keyed-signed-factory-release-submission-intent-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_SCOPE: &str =
    "durable-idempotency-keyed-signed-factory-release-adapter-receipt-v1";
pub(crate) const SIGNED_FACTORY_RELEASE_ADAPTER_ACKNOWLEDGEMENT_SCOPE: &str =
    "pcbex-signed-factory-release-adapter-acknowledgement-v1";
const IDEMPOTENCY_KEY_DOMAIN: &[u8] =
    b"pcbex:durable-signed-factory-release-submission-idempotency-v1\0";
const INTENT_BINDING_DOMAIN: &[u8] = b"pcbex:durable-signed-factory-release-submission-intent-v1\0";
const RECEIPT_BINDING_DOMAIN: &[u8] = b"pcbex:durable-signed-factory-release-adapter-receipt-v1\0";

pub(crate) const MAX_SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_BYTES: u64 = 16 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_BYTES: u64 = 32 * 1024;
pub(crate) const MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES: u64 = 64 * 1024;
const MAX_ENDPOINT_CHARS: usize = 2048;
const MAX_SUBMISSION_ID_CHARS: usize = 256;
const MAXIMUM_TIMESTAMP: u64 = 9_223_372_036_854_775_807;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FactoryReleaseAdapterOperation {
    Submit,
    Reconcile,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FactoryReleaseAdapterStatus {
    AdapterAccepted,
    AdapterRejected,
    AdapterPending,
    OutcomeUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseArtifactIdentity {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseSubmissionIntent {
    pub(crate) schema_version: u32,
    pub(crate) intent_scope: String,
    pub(crate) local_submission_intent_committed: bool,
    pub(crate) server_side_idempotency_enforced: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) ledger_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) request_nonce: String,
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) submission_endpoint: String,
    pub(crate) reservation_challenge: String,
    pub(crate) release_subject_sha256: String,
    pub(crate) reservation_marker_sha256: String,
    pub(crate) manufacturing_package: FactoryReleaseArtifactIdentity,
    pub(crate) binding_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterAcknowledgement {
    pub(crate) schema_version: u32,
    pub(crate) acknowledgement_scope: String,
    pub(crate) operation: FactoryReleaseAdapterOperation,
    pub(crate) idempotency_key: String,
    pub(crate) request_nonce: String,
    pub(crate) reconciliation_id: Option<String>,
    pub(crate) release_subject_sha256: String,
    pub(crate) manufacturing_package_sha256: String,
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) status: FactoryReleaseAdapterStatus,
    pub(crate) submission_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedFactoryReleaseAdapterReceipt {
    pub(crate) schema_version: u32,
    pub(crate) receipt_scope: String,
    pub(crate) operation: FactoryReleaseAdapterOperation,
    pub(crate) status: FactoryReleaseAdapterStatus,
    pub(crate) accepted: bool,
    pub(crate) adapter_network_performed: bool,
    pub(crate) manufacturing_package_transmission_attempted: bool,
    pub(crate) external_submission_attempted: bool,
    pub(crate) acknowledgement_validated: bool,
    pub(crate) local_submission_intent_committed: bool,
    pub(crate) server_side_idempotency_enforced: bool,
    pub(crate) factory_legal_identity_verified: bool,
    pub(crate) endpoint_transport_authenticity_verified: bool,
    pub(crate) raw_response_authenticity_verified: bool,
    pub(crate) trusted_time_verified: bool,
    pub(crate) capacity_reserved: bool,
    pub(crate) order_placed: bool,
    pub(crate) payment_performed: bool,
    pub(crate) exactly_once_execution_verified: bool,
    pub(crate) ledger_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) request_nonce: String,
    pub(crate) reconciliation_id: Option<String>,
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) endpoint: String,
    pub(crate) reservation_challenge: String,
    pub(crate) release_subject_sha256: String,
    pub(crate) manufacturing_package: FactoryReleaseArtifactIdentity,
    pub(crate) intent_sha256: String,
    pub(crate) http_status: Option<u16>,
    pub(crate) response_bytes: Option<u64>,
    pub(crate) response_sha256: Option<String>,
    pub(crate) submission_id: Option<String>,
    pub(crate) failure: Option<String>,
    pub(crate) attempted_at_unix: u64,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct IdempotencyKeyMaterial<'a> {
    schema_version: u32,
    ledger_id: &'a str,
    factory_id: &'a str,
    provider: FactoryProvider,
    reservation_challenge: &'a str,
    release_subject_sha256: &'a str,
    reservation_marker_sha256: &'a str,
    manufacturing_package: &'a FactoryReleaseArtifactIdentity,
}

#[derive(Serialize)]
struct IntentBinding<'a> {
    schema_version: u32,
    intent_scope: &'a str,
    local_submission_intent_committed: bool,
    server_side_idempotency_enforced: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    ledger_id: &'a str,
    idempotency_key: &'a str,
    request_nonce: &'a str,
    factory_id: &'a str,
    provider: FactoryProvider,
    submission_endpoint: &'a str,
    reservation_challenge: &'a str,
    release_subject_sha256: &'a str,
    reservation_marker_sha256: &'a str,
    manufacturing_package: &'a FactoryReleaseArtifactIdentity,
}

#[derive(Serialize)]
struct ReceiptBinding<'a> {
    schema_version: u32,
    receipt_scope: &'a str,
    operation: FactoryReleaseAdapterOperation,
    status: FactoryReleaseAdapterStatus,
    accepted: bool,
    adapter_network_performed: bool,
    manufacturing_package_transmission_attempted: bool,
    external_submission_attempted: bool,
    acknowledgement_validated: bool,
    local_submission_intent_committed: bool,
    server_side_idempotency_enforced: bool,
    factory_legal_identity_verified: bool,
    endpoint_transport_authenticity_verified: bool,
    raw_response_authenticity_verified: bool,
    trusted_time_verified: bool,
    capacity_reserved: bool,
    order_placed: bool,
    payment_performed: bool,
    exactly_once_execution_verified: bool,
    ledger_id: &'a str,
    idempotency_key: &'a str,
    request_nonce: &'a str,
    reconciliation_id: &'a Option<String>,
    factory_id: &'a str,
    provider: FactoryProvider,
    endpoint: &'a str,
    reservation_challenge: &'a str,
    release_subject_sha256: &'a str,
    manufacturing_package: &'a FactoryReleaseArtifactIdentity,
    intent_sha256: &'a str,
    http_status: &'a Option<u16>,
    response_bytes: &'a Option<u64>,
    response_sha256: &'a Option<String>,
    submission_id: &'a Option<String>,
    failure: &'a Option<String>,
    attempted_at_unix: u64,
}

pub(crate) fn build_signed_factory_release_submission_intent(
    marker: &SignedFactoryReceiptReleaseReservation,
    reservation_marker_sha256: &str,
    package_bytes: u64,
    package_sha256: &str,
    endpoint: &str,
    request_nonce: &str,
    allow_http_loopback: bool,
) -> Result<SignedFactoryReleaseSubmissionIntent, String> {
    validate_digest(reservation_marker_sha256, "reservation marker SHA-256")?;
    validate_digest(package_sha256, "manufacturing package SHA-256")?;
    validate_digest(request_nonce, "factory release request nonce")?;
    validate_endpoint(endpoint, allow_http_loopback)?;
    if endpoint.chars().count() > MAX_ENDPOINT_CHARS {
        return Err(format!(
            "factory release submission endpoint exceeds {MAX_ENDPOINT_CHARS} characters"
        ));
    }
    if package_bytes == 0 || package_bytes > crate::manufacturing_limits::MAX_PACKAGE_BYTES {
        return Err("manufacturing package byte count is outside its bound".into());
    }
    let summary = &marker.release_report_summary;
    if marker.ledger_id.is_empty()
        || summary.manufacturing_package_sha256 != package_sha256
        || !summary.release_authenticated
    {
        return Err(
            "signed release reservation does not bind the selected manufacturing package".into(),
        );
    }
    let provider = FactoryProvider::parse(&summary.provider)?;
    let package = FactoryReleaseArtifactIdentity {
        bytes: package_bytes,
        sha256: package_sha256.into(),
    };
    let key_material = IdempotencyKeyMaterial {
        schema_version: SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION,
        ledger_id: &marker.ledger_id,
        factory_id: &summary.factory_id,
        provider,
        reservation_challenge: &summary.challenge,
        release_subject_sha256: &summary.release_subject_sha256,
        reservation_marker_sha256,
        manufacturing_package: &package,
    };
    let idempotency_key = domain_hash(IDEMPOTENCY_KEY_DOMAIN, &key_material)?;
    let mut intent = SignedFactoryReleaseSubmissionIntent {
        schema_version: SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION,
        intent_scope: SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_SCOPE.into(),
        local_submission_intent_committed: true,
        server_side_idempotency_enforced: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        ledger_id: marker.ledger_id.clone(),
        idempotency_key,
        request_nonce: request_nonce.into(),
        factory_id: summary.factory_id.clone(),
        provider,
        submission_endpoint: endpoint.into(),
        reservation_challenge: summary.challenge.clone(),
        release_subject_sha256: summary.release_subject_sha256.clone(),
        reservation_marker_sha256: reservation_marker_sha256.into(),
        manufacturing_package: package,
        binding_sha256: String::new(),
    };
    intent.binding_sha256 = intent_binding(&intent)?;
    validate_signed_factory_release_submission_intent(&intent)?;
    Ok(intent)
}

pub(crate) fn render_signed_factory_release_submission_intent(
    intent: &SignedFactoryReleaseSubmissionIntent,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_submission_intent(intent)?;
    render_bounded(
        intent,
        MAX_SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_BYTES,
        "signed factory release submission intent",
    )
}

pub(crate) fn parse_signed_factory_release_submission_intent(
    source: &[u8],
) -> Result<SignedFactoryReleaseSubmissionIntent, String> {
    let intent = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_BYTES,
        "signed factory release submission intent",
    )?;
    validate_signed_factory_release_submission_intent(&intent)?;
    Ok(intent)
}

pub(crate) fn render_signed_factory_release_adapter_receipt(
    receipt: &SignedFactoryReleaseAdapterReceipt,
) -> Result<Vec<u8>, String> {
    validate_signed_factory_release_adapter_receipt(receipt, None)?;
    render_bounded(
        receipt,
        MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_BYTES,
        "signed factory release adapter receipt",
    )
}

pub(crate) fn parse_signed_factory_release_adapter_receipt(
    source: &[u8],
    intent: &SignedFactoryReleaseSubmissionIntent,
) -> Result<SignedFactoryReleaseAdapterReceipt, String> {
    let receipt = parse_canonical(
        source,
        MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_BYTES,
        "signed factory release adapter receipt",
    )?;
    validate_signed_factory_release_adapter_receipt(&receipt, Some(intent))?;
    Ok(receipt)
}

pub(crate) fn signed_factory_release_submission_intent_filename(
    idempotency_key: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    Ok(format!(
        "signed-factory-release-submission-intent-v1-{idempotency_key}.json"
    ))
}

pub(crate) fn signed_factory_release_submission_result_filename(
    idempotency_key: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    Ok(format!(
        "signed-factory-release-submission-result-v1-{idempotency_key}.json"
    ))
}

pub(crate) fn signed_factory_release_reconciliation_filename(
    idempotency_key: &str,
    reconciliation_id: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_digest(reconciliation_id, "factory release reconciliation id")?;
    Ok(format!(
        "signed-factory-release-reconciliation-v1-{idempotency_key}-{reconciliation_id}.json"
    ))
}

pub(crate) fn load_factory_release_bearer_token(variable: &str) -> Result<String, String> {
    validate_env_name(variable)?;
    let token = env::var(variable)
        .map_err(|_| "factory release bearer-token environment is unset".to_string())?;
    validate_bearer_token(&token)?;
    Ok(token)
}

pub(crate) fn submit_signed_factory_release_adapter(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    package: &[u8],
    bearer_token: &str,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    attempted_at_unix: u64,
) -> Result<SignedFactoryReleaseAdapterReceipt, String> {
    validate_signed_factory_release_submission_intent(intent)?;
    validate_intent_sha256(intent, intent_sha256)?;
    validate_timestamp(attempted_at_unix)?;
    validate_timeout(timeout_seconds)?;
    validate_endpoint(&intent.submission_endpoint, allow_http_loopback)?;
    validate_bearer_token(bearer_token)?;
    if sha256(package) != intent.manufacturing_package.sha256
        || package.len() as u64 != intent.manufacturing_package.bytes
    {
        return Err("manufacturing package does not match the durable submission intent".into());
    }
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .http_status_as_error(false)
        .build();
    let agent: ureq::Agent = config.into();
    let call = agent
        .post(&intent.submission_endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/zip")
        .header("User-Agent", concat!("pcbex/", env!("CARGO_PKG_VERSION")))
        .header("X-PCBEX-Adapter", "signed-factory-release-http-v1")
        .header("X-PCBEX-Schema-Version", "1")
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
        .header("Authorization", &format!("Bearer {bearer_token}"));
    let response = call.send(package);
    receipt_from_response(
        intent,
        intent_sha256,
        FactoryReleaseAdapterOperation::Submit,
        None,
        &intent.submission_endpoint,
        bearer_token,
        attempted_at_unix,
        response,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_signed_factory_release_adapter(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    endpoint: &str,
    reconciliation_id: &str,
    bearer_token: &str,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    attempted_at_unix: u64,
) -> Result<SignedFactoryReleaseAdapterReceipt, String> {
    validate_signed_factory_release_submission_intent(intent)?;
    validate_intent_sha256(intent, intent_sha256)?;
    validate_digest(reconciliation_id, "factory release reconciliation id")?;
    validate_timestamp(attempted_at_unix)?;
    validate_timeout(timeout_seconds)?;
    validate_endpoint(endpoint, allow_http_loopback)?;
    validate_bearer_token(bearer_token)?;
    if endpoint.chars().count() > MAX_ENDPOINT_CHARS {
        return Err(format!(
            "factory release reconciliation endpoint exceeds {MAX_ENDPOINT_CHARS} characters"
        ));
    }
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
    receipt_from_response(
        intent,
        intent_sha256,
        FactoryReleaseAdapterOperation::Reconcile,
        Some(reconciliation_id),
        endpoint,
        bearer_token,
        attempted_at_unix,
        response,
    )
}

#[allow(clippy::too_many_arguments)]
fn receipt_from_response(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
    bearer_token: &str,
    attempted_at_unix: u64,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<SignedFactoryReleaseAdapterReceipt, String> {
    let mut response = match response {
        Ok(response) => response,
        Err(_) => {
            return build_receipt(
                intent,
                intent_sha256,
                operation,
                reconciliation_id,
                endpoint,
                attempted_at_unix,
                None,
                None,
                None,
                None,
                Some("transport_error"),
            );
        }
    };
    let http_status = response.status().as_u16();
    let content_type_valid = response
        .body()
        .mime_type()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"));
    let response_bytes = match response
        .body_mut()
        .with_config()
        .limit(MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES + 1)
        .read_to_vec()
    {
        Ok(bytes)
            if !bytes.is_empty()
                && bytes.len() as u64 <= MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES =>
        {
            bytes
        }
        _ => {
            return build_receipt(
                intent,
                intent_sha256,
                operation,
                reconciliation_id,
                endpoint,
                attempted_at_unix,
                Some(http_status),
                None,
                None,
                None,
                Some("response_size_invalid"),
            );
        }
    };
    let response_identity = (response_bytes.len() as u64, sha256(&response_bytes));
    if response_contains_bearer_token(&response_bytes, &Value::Null, bearer_token) {
        return build_receipt(
            intent,
            intent_sha256,
            operation,
            reconciliation_id,
            endpoint,
            attempted_at_unix,
            Some(http_status),
            Some(response_identity.0),
            Some(&response_identity.1),
            None,
            Some("credential_reflection_detected"),
        );
    }
    if !(200..=299).contains(&http_status) {
        return build_receipt(
            intent,
            intent_sha256,
            operation,
            reconciliation_id,
            endpoint,
            attempted_at_unix,
            Some(http_status),
            Some(response_identity.0),
            Some(&response_identity.1),
            None,
            Some("unexpected_http_status"),
        );
    }
    if !content_type_valid {
        return build_receipt(
            intent,
            intent_sha256,
            operation,
            reconciliation_id,
            endpoint,
            attempted_at_unix,
            Some(http_status),
            Some(response_identity.0),
            Some(&response_identity.1),
            None,
            Some("response_content_type_invalid"),
        );
    }
    if reject_duplicate_json_keys(&response_bytes).is_err() {
        return build_receipt(
            intent,
            intent_sha256,
            operation,
            reconciliation_id,
            endpoint,
            attempted_at_unix,
            Some(http_status),
            Some(response_identity.0),
            Some(&response_identity.1),
            None,
            Some("response_json_invalid"),
        );
    }
    let value: Value = match serde_json::from_slice(&response_bytes) {
        Ok(value) => value,
        Err(_) => {
            return build_receipt(
                intent,
                intent_sha256,
                operation,
                reconciliation_id,
                endpoint,
                attempted_at_unix,
                Some(http_status),
                Some(response_identity.0),
                Some(&response_identity.1),
                None,
                Some("response_json_invalid"),
            );
        }
    };
    if response_contains_bearer_token(&response_bytes, &value, bearer_token) {
        return build_receipt(
            intent,
            intent_sha256,
            operation,
            reconciliation_id,
            endpoint,
            attempted_at_unix,
            Some(http_status),
            Some(response_identity.0),
            Some(&response_identity.1),
            None,
            Some("credential_reflection_detected"),
        );
    }
    let acknowledgement: FactoryReleaseAdapterAcknowledgement = match serde_json::from_value(value)
    {
        Ok(acknowledgement) => acknowledgement,
        Err(_) => {
            return build_receipt(
                intent,
                intent_sha256,
                operation,
                reconciliation_id,
                endpoint,
                attempted_at_unix,
                Some(http_status),
                Some(response_identity.0),
                Some(&response_identity.1),
                None,
                Some("response_json_invalid"),
            );
        }
    };
    if validate_acknowledgement(&acknowledgement, intent, operation, reconciliation_id).is_err() {
        return build_receipt(
            intent,
            intent_sha256,
            operation,
            reconciliation_id,
            endpoint,
            attempted_at_unix,
            Some(http_status),
            Some(response_identity.0),
            Some(&response_identity.1),
            None,
            Some("response_binding_mismatch"),
        );
    }
    build_receipt(
        intent,
        intent_sha256,
        operation,
        reconciliation_id,
        endpoint,
        attempted_at_unix,
        Some(http_status),
        Some(response_identity.0),
        Some(&response_identity.1),
        Some(&acknowledgement),
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_receipt(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
    attempted_at_unix: u64,
    http_status: Option<u16>,
    response_bytes: Option<u64>,
    response_sha256: Option<&str>,
    acknowledgement: Option<&FactoryReleaseAdapterAcknowledgement>,
    failure: Option<&str>,
) -> Result<SignedFactoryReleaseAdapterReceipt, String> {
    let status = acknowledgement
        .map(|acknowledgement| acknowledgement.status)
        .unwrap_or(FactoryReleaseAdapterStatus::OutcomeUnknown);
    let mut receipt = SignedFactoryReleaseAdapterReceipt {
        schema_version: SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION,
        receipt_scope: SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_SCOPE.into(),
        operation,
        status,
        accepted: status == FactoryReleaseAdapterStatus::AdapterAccepted,
        adapter_network_performed: true,
        manufacturing_package_transmission_attempted: operation
            == FactoryReleaseAdapterOperation::Submit,
        external_submission_attempted: operation == FactoryReleaseAdapterOperation::Submit,
        acknowledgement_validated: acknowledgement.is_some(),
        local_submission_intent_committed: true,
        server_side_idempotency_enforced: false,
        factory_legal_identity_verified: false,
        endpoint_transport_authenticity_verified: false,
        raw_response_authenticity_verified: false,
        trusted_time_verified: false,
        capacity_reserved: false,
        order_placed: false,
        payment_performed: false,
        exactly_once_execution_verified: false,
        ledger_id: intent.ledger_id.clone(),
        idempotency_key: intent.idempotency_key.clone(),
        request_nonce: intent.request_nonce.clone(),
        reconciliation_id: reconciliation_id.map(str::to_owned),
        factory_id: intent.factory_id.clone(),
        provider: intent.provider,
        endpoint: endpoint.into(),
        reservation_challenge: intent.reservation_challenge.clone(),
        release_subject_sha256: intent.release_subject_sha256.clone(),
        manufacturing_package: intent.manufacturing_package.clone(),
        intent_sha256: intent_sha256.into(),
        http_status,
        response_bytes,
        response_sha256: response_sha256.map(str::to_owned),
        submission_id: acknowledgement.map(|value| value.submission_id.clone()),
        failure: failure.map(str::to_owned),
        attempted_at_unix,
        binding_sha256: String::new(),
    };
    receipt.binding_sha256 = receipt_binding(&receipt)?;
    validate_signed_factory_release_adapter_receipt(&receipt, Some(intent))?;
    Ok(receipt)
}

fn validate_signed_factory_release_submission_intent(
    intent: &SignedFactoryReleaseSubmissionIntent,
) -> Result<(), String> {
    if intent.schema_version != SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION
        || intent.intent_scope != SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_SCOPE
        || !intent.local_submission_intent_committed
        || intent.server_side_idempotency_enforced
        || intent.capacity_reserved
        || intent.order_placed
        || intent.payment_performed
    {
        return Err(
            "signed factory release submission intent identity or nonclaims are invalid".into(),
        );
    }
    for (value, label) in [
        (&intent.ledger_id, "factory release ledger id"),
        (&intent.idempotency_key, "factory release idempotency key"),
        (&intent.request_nonce, "factory release request nonce"),
        (
            &intent.reservation_challenge,
            "factory release reservation challenge",
        ),
        (
            &intent.release_subject_sha256,
            "signed release subject SHA-256",
        ),
        (
            &intent.reservation_marker_sha256,
            "reservation marker SHA-256",
        ),
        (
            &intent.manufacturing_package.sha256,
            "manufacturing package SHA-256",
        ),
        (
            &intent.binding_sha256,
            "factory release intent binding SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    validate_slug(&intent.factory_id, "factory id")?;
    // Canonical retained test receipts may name an explicitly enabled
    // loopback HTTP endpoint. Production construction still validates with
    // `allow_http_loopback = false` at its public boundary.
    validate_endpoint(&intent.submission_endpoint, true)?;
    if intent.submission_endpoint.chars().count() > MAX_ENDPOINT_CHARS
        || intent.manufacturing_package.bytes == 0
        || intent.manufacturing_package.bytes > crate::manufacturing_limits::MAX_PACKAGE_BYTES
    {
        return Err("signed factory release submission intent bounds are invalid".into());
    }
    let material = IdempotencyKeyMaterial {
        schema_version: intent.schema_version,
        ledger_id: &intent.ledger_id,
        factory_id: &intent.factory_id,
        provider: intent.provider,
        reservation_challenge: &intent.reservation_challenge,
        release_subject_sha256: &intent.release_subject_sha256,
        reservation_marker_sha256: &intent.reservation_marker_sha256,
        manufacturing_package: &intent.manufacturing_package,
    };
    if intent.idempotency_key != domain_hash(IDEMPOTENCY_KEY_DOMAIN, &material)? {
        return Err("factory release idempotency key does not match the bound intent".into());
    }
    if intent.binding_sha256 != intent_binding(intent)? {
        return Err("signed factory release submission intent binding is invalid".into());
    }
    Ok(())
}

fn validate_signed_factory_release_adapter_receipt(
    receipt: &SignedFactoryReleaseAdapterReceipt,
    intent: Option<&SignedFactoryReleaseSubmissionIntent>,
) -> Result<(), String> {
    if receipt.schema_version != SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION
        || receipt.receipt_scope != SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_SCOPE
        || !receipt.adapter_network_performed
        || !receipt.local_submission_intent_committed
        || receipt.server_side_idempotency_enforced
        || receipt.factory_legal_identity_verified
        || receipt.endpoint_transport_authenticity_verified
        || receipt.raw_response_authenticity_verified
        || receipt.trusted_time_verified
        || receipt.capacity_reserved
        || receipt.order_placed
        || receipt.payment_performed
        || receipt.exactly_once_execution_verified
    {
        return Err(
            "signed factory release adapter receipt identity or nonclaims are invalid".into(),
        );
    }
    let submit = receipt.operation == FactoryReleaseAdapterOperation::Submit;
    if receipt.manufacturing_package_transmission_attempted != submit
        || receipt.external_submission_attempted != submit
        || receipt.reconciliation_id.is_some() == submit
    {
        return Err("signed factory release adapter operation flags are invalid".into());
    }
    for (value, label) in [
        (&receipt.ledger_id, "factory release ledger id"),
        (&receipt.idempotency_key, "factory release idempotency key"),
        (&receipt.request_nonce, "factory release request nonce"),
        (
            &receipt.reservation_challenge,
            "factory release reservation challenge",
        ),
        (
            &receipt.release_subject_sha256,
            "signed release subject SHA-256",
        ),
        (
            &receipt.manufacturing_package.sha256,
            "manufacturing package SHA-256",
        ),
        (&receipt.intent_sha256, "factory release intent SHA-256"),
        (
            &receipt.binding_sha256,
            "factory release receipt binding SHA-256",
        ),
    ] {
        validate_digest(value, label)?;
    }
    if let Some(value) = receipt.reconciliation_id.as_deref() {
        validate_digest(value, "factory release reconciliation id")?;
    }
    if let Some(value) = receipt.response_sha256.as_deref() {
        validate_digest(value, "factory release response SHA-256")?;
    }
    validate_slug(&receipt.factory_id, "factory id")?;
    validate_endpoint(&receipt.endpoint, true)?;
    validate_timestamp(receipt.attempted_at_unix)?;
    if receipt.endpoint.chars().count() > MAX_ENDPOINT_CHARS
        || receipt.manufacturing_package.bytes == 0
        || receipt.manufacturing_package.bytes > crate::manufacturing_limits::MAX_PACKAGE_BYTES
    {
        return Err("signed factory release adapter receipt bounds are invalid".into());
    }
    let unknown = receipt.status == FactoryReleaseAdapterStatus::OutcomeUnknown;
    if receipt.accepted != (receipt.status == FactoryReleaseAdapterStatus::AdapterAccepted)
        || receipt.acknowledgement_validated == unknown
        || receipt.failure.is_some() != unknown
        || receipt.submission_id.is_some() == unknown
        || (!unknown
            && (receipt.http_status.is_none()
                || receipt.response_bytes.is_none()
                || receipt.response_sha256.is_none()))
    {
        return Err("signed factory release adapter result flags are invalid".into());
    }
    if let Some(status) = receipt.http_status
        && !(100..=599).contains(&status)
    {
        return Err("factory release HTTP status is outside its bound".into());
    }
    if let Some(bytes) = receipt.response_bytes
        && (bytes == 0 || bytes > MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES)
    {
        return Err("factory release response byte count is outside its bound".into());
    }
    if let Some(submission_id) = receipt.submission_id.as_deref() {
        validate_submission_id(submission_id)?;
    }
    if let Some(failure) = receipt.failure.as_deref()
        && !matches!(
            failure,
            "transport_error"
                | "response_size_invalid"
                | "credential_reflection_detected"
                | "unexpected_http_status"
                | "response_content_type_invalid"
                | "response_json_invalid"
                | "response_binding_mismatch"
        )
    {
        return Err("factory release adapter failure code is invalid".into());
    }
    let response_identity_complete = receipt.response_bytes.is_some();
    if response_identity_complete != receipt.response_sha256.is_some() {
        return Err("factory release adapter response identity is incomplete".into());
    }
    if unknown {
        let failure = receipt
            .failure
            .as_deref()
            .ok_or_else(|| "factory release adapter unknown result has no failure".to_string())?;
        let valid_shape = match failure {
            "transport_error" => receipt.http_status.is_none() && !response_identity_complete,
            "response_size_invalid" => receipt.http_status.is_some() && !response_identity_complete,
            "credential_reflection_detected" => {
                receipt.http_status.is_some() && response_identity_complete
            }
            "unexpected_http_status" => {
                matches!(receipt.http_status, Some(status) if !(200..=299).contains(&status))
                    && response_identity_complete
            }
            "response_content_type_invalid"
            | "response_json_invalid"
            | "response_binding_mismatch" => {
                matches!(receipt.http_status, Some(200..=299)) && response_identity_complete
            }
            _ => false,
        };
        if !valid_shape {
            return Err("factory release adapter unknown result shape is invalid".into());
        }
    } else if !matches!(receipt.http_status, Some(200..=299)) {
        return Err("validated factory release acknowledgement requires a 2xx response".into());
    }
    if let Some(intent) = intent
        && (receipt.ledger_id != intent.ledger_id
            || receipt.idempotency_key != intent.idempotency_key
            || receipt.request_nonce != intent.request_nonce
            || receipt.factory_id != intent.factory_id
            || receipt.provider != intent.provider
            || receipt.reservation_challenge != intent.reservation_challenge
            || receipt.release_subject_sha256 != intent.release_subject_sha256
            || receipt.manufacturing_package != intent.manufacturing_package
            || validate_intent_sha256(intent, &receipt.intent_sha256).is_err()
            || (submit && receipt.endpoint != intent.submission_endpoint))
    {
        return Err("factory release adapter receipt does not match its durable intent".into());
    }
    if receipt.binding_sha256 != receipt_binding(receipt)? {
        return Err("signed factory release adapter receipt binding is invalid".into());
    }
    Ok(())
}

fn validate_acknowledgement(
    acknowledgement: &FactoryReleaseAdapterAcknowledgement,
    intent: &SignedFactoryReleaseSubmissionIntent,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
) -> Result<(), String> {
    if acknowledgement.schema_version != SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION
        || acknowledgement.acknowledgement_scope
            != SIGNED_FACTORY_RELEASE_ADAPTER_ACKNOWLEDGEMENT_SCOPE
        || acknowledgement.operation != operation
        || acknowledgement.idempotency_key != intent.idempotency_key
        || acknowledgement.request_nonce != intent.request_nonce
        || acknowledgement.reconciliation_id.as_deref() != reconciliation_id
        || acknowledgement.release_subject_sha256 != intent.release_subject_sha256
        || acknowledgement.manufacturing_package_sha256 != intent.manufacturing_package.sha256
        || acknowledgement.factory_id != intent.factory_id
        || acknowledgement.provider != intent.provider
        || acknowledgement.status == FactoryReleaseAdapterStatus::OutcomeUnknown
    {
        return Err("factory release adapter acknowledgement binding is invalid".into());
    }
    validate_submission_id(&acknowledgement.submission_id)
}

fn intent_binding(intent: &SignedFactoryReleaseSubmissionIntent) -> Result<String, String> {
    domain_hash(
        INTENT_BINDING_DOMAIN,
        &IntentBinding {
            schema_version: intent.schema_version,
            intent_scope: &intent.intent_scope,
            local_submission_intent_committed: intent.local_submission_intent_committed,
            server_side_idempotency_enforced: intent.server_side_idempotency_enforced,
            capacity_reserved: intent.capacity_reserved,
            order_placed: intent.order_placed,
            payment_performed: intent.payment_performed,
            ledger_id: &intent.ledger_id,
            idempotency_key: &intent.idempotency_key,
            request_nonce: &intent.request_nonce,
            factory_id: &intent.factory_id,
            provider: intent.provider,
            submission_endpoint: &intent.submission_endpoint,
            reservation_challenge: &intent.reservation_challenge,
            release_subject_sha256: &intent.release_subject_sha256,
            reservation_marker_sha256: &intent.reservation_marker_sha256,
            manufacturing_package: &intent.manufacturing_package,
        },
    )
}

fn receipt_binding(receipt: &SignedFactoryReleaseAdapterReceipt) -> Result<String, String> {
    domain_hash(
        RECEIPT_BINDING_DOMAIN,
        &ReceiptBinding {
            schema_version: receipt.schema_version,
            receipt_scope: &receipt.receipt_scope,
            operation: receipt.operation,
            status: receipt.status,
            accepted: receipt.accepted,
            adapter_network_performed: receipt.adapter_network_performed,
            manufacturing_package_transmission_attempted: receipt
                .manufacturing_package_transmission_attempted,
            external_submission_attempted: receipt.external_submission_attempted,
            acknowledgement_validated: receipt.acknowledgement_validated,
            local_submission_intent_committed: receipt.local_submission_intent_committed,
            server_side_idempotency_enforced: receipt.server_side_idempotency_enforced,
            factory_legal_identity_verified: receipt.factory_legal_identity_verified,
            endpoint_transport_authenticity_verified: receipt
                .endpoint_transport_authenticity_verified,
            raw_response_authenticity_verified: receipt.raw_response_authenticity_verified,
            trusted_time_verified: receipt.trusted_time_verified,
            capacity_reserved: receipt.capacity_reserved,
            order_placed: receipt.order_placed,
            payment_performed: receipt.payment_performed,
            exactly_once_execution_verified: receipt.exactly_once_execution_verified,
            ledger_id: &receipt.ledger_id,
            idempotency_key: &receipt.idempotency_key,
            request_nonce: &receipt.request_nonce,
            reconciliation_id: &receipt.reconciliation_id,
            factory_id: &receipt.factory_id,
            provider: receipt.provider,
            endpoint: &receipt.endpoint,
            reservation_challenge: &receipt.reservation_challenge,
            release_subject_sha256: &receipt.release_subject_sha256,
            manufacturing_package: &receipt.manufacturing_package,
            intent_sha256: &receipt.intent_sha256,
            http_status: &receipt.http_status,
            response_bytes: &receipt.response_bytes,
            response_sha256: &receipt.response_sha256,
            submission_id: &receipt.submission_id,
            failure: &receipt.failure,
            attempted_at_unix: receipt.attempted_at_unix,
        },
    )
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> Result<String, String> {
    let bytes = serde_json::to_vec(value)
        .map_err(|error| format!("serializing signed factory release binding: {error}"))?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}

fn render_bounded(value: &impl Serialize, maximum: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut raw =
        serde_json::to_vec_pretty(value).map_err(|error| format!("rendering {label}: {error}"))?;
    raw.push(b'\n');
    if raw.is_empty() || raw.len() as u64 > maximum {
        return Err(format!("{label} exceeds the {maximum}-byte limit"));
    }
    Ok(raw)
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

fn validate_timeout(value: u64) -> Result<(), String> {
    if !(1..=600).contains(&value) {
        return Err("factory release timeout must be between 1 and 600 seconds".into());
    }
    Ok(())
}

fn validate_intent_sha256(
    intent: &SignedFactoryReleaseSubmissionIntent,
    expected: &str,
) -> Result<(), String> {
    validate_digest(expected, "factory release submission intent SHA-256")?;
    let canonical = render_bounded(
        intent,
        MAX_SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_BYTES,
        "signed factory release submission intent",
    )?;
    if sha256(&canonical) != expected {
        return Err("factory release submission intent SHA-256 does not match its bytes".into());
    }
    Ok(())
}

fn validate_timestamp(value: u64) -> Result<(), String> {
    if value > MAXIMUM_TIMESTAMP {
        return Err("factory release timestamp is outside its bound".into());
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

fn validate_submission_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().count() > MAX_SUBMISSION_ID_CHARS
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
    {
        return Err("factory release submission id is invalid".into());
    }
    Ok(())
}

pub(crate) fn signed_factory_release_submission_intent_json_schema() -> Value {
    let digest = digest_schema();
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-submission-intent-v1.json",
        "title": "pcbex signed factory release durable submission intent",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "intent_scope", "local_submission_intent_committed",
            "server_side_idempotency_enforced", "capacity_reserved", "order_placed",
            "payment_performed", "ledger_id", "idempotency_key", "request_nonce",
            "factory_id", "provider", "submission_endpoint", "reservation_challenge",
            "release_subject_sha256", "reservation_marker_sha256",
            "manufacturing_package", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "intent_scope": {"const": SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_SCOPE},
            "local_submission_intent_committed": {"const": true},
            "server_side_idempotency_enforced": false_value,
            "capacity_reserved": false_value,
            "order_placed": false_value,
            "payment_performed": false_value,
            "ledger_id": digest,
            "idempotency_key": digest,
            "request_nonce": digest,
            "factory_id": slug_schema(),
            "provider": provider_schema(),
            "submission_endpoint": endpoint_schema(),
            "reservation_challenge": digest,
            "release_subject_sha256": digest,
            "reservation_marker_sha256": digest,
            "manufacturing_package": artifact_schema(),
            "binding_sha256": digest
        }
    })
}

pub(crate) fn signed_factory_release_adapter_acknowledgement_json_schema() -> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-adapter-acknowledgement-v1.json",
        "title": "pcbex signed factory release adapter acknowledgement",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "acknowledgement_scope", "operation", "idempotency_key",
            "request_nonce", "reconciliation_id", "release_subject_sha256",
            "manufacturing_package_sha256", "factory_id", "provider", "status",
            "submission_id"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "acknowledgement_scope": {"const": SIGNED_FACTORY_RELEASE_ADAPTER_ACKNOWLEDGEMENT_SCOPE},
            "operation": {"enum": ["submit", "reconcile"]},
            "idempotency_key": digest,
            "request_nonce": digest,
            "reconciliation_id": {"oneOf": [{"type": "null"}, digest]},
            "release_subject_sha256": digest,
            "manufacturing_package_sha256": digest,
            "factory_id": slug_schema(),
            "provider": provider_schema(),
            "status": {"enum": ["adapter_accepted", "adapter_rejected", "adapter_pending"]},
            "submission_id": {
                "type": "string", "minLength": 1, "maxLength": MAX_SUBMISSION_ID_CHARS,
                "pattern": "^[^\\s\\\"\\\\]+$"
            }
        },
        "allOf": [
            {
                "if": {"properties": {"operation": {"const": "submit"}}, "required": ["operation"]},
                "then": {"properties": {"reconciliation_id": {"type": "null"}}}
            },
            {
                "if": {"properties": {"operation": {"const": "reconcile"}}, "required": ["operation"]},
                "then": {"properties": {"reconciliation_id": digest}}
            }
        ]
    })
}

pub(crate) fn signed_factory_release_adapter_receipt_json_schema() -> Value {
    let digest = digest_schema();
    let false_value = json!({"const": false});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/signed-factory-release-adapter-receipt-v1.json",
        "title": "pcbex durable signed factory release adapter receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "receipt_scope", "operation", "status", "accepted",
            "adapter_network_performed", "manufacturing_package_transmission_attempted",
            "external_submission_attempted", "acknowledgement_validated",
            "local_submission_intent_committed", "server_side_idempotency_enforced",
            "factory_legal_identity_verified", "endpoint_transport_authenticity_verified",
            "raw_response_authenticity_verified", "trusted_time_verified",
            "capacity_reserved", "order_placed",
            "payment_performed", "exactly_once_execution_verified", "ledger_id",
            "idempotency_key", "request_nonce", "reconciliation_id", "factory_id",
            "provider", "endpoint", "reservation_challenge", "release_subject_sha256",
            "manufacturing_package", "intent_sha256", "http_status", "response_bytes",
            "response_sha256", "submission_id", "failure", "attempted_at_unix",
            "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "receipt_scope": {"const": SIGNED_FACTORY_RELEASE_ADAPTER_RECEIPT_SCOPE},
            "operation": {"enum": ["submit", "reconcile"]},
            "status": {"enum": ["adapter_accepted", "adapter_rejected", "adapter_pending", "outcome_unknown"]},
            "accepted": {"type": "boolean"},
            "adapter_network_performed": {"const": true},
            "manufacturing_package_transmission_attempted": {"type": "boolean"},
            "external_submission_attempted": {"type": "boolean"},
            "acknowledgement_validated": {"type": "boolean"},
            "local_submission_intent_committed": {"const": true},
            "server_side_idempotency_enforced": false_value,
            "factory_legal_identity_verified": false_value,
            "endpoint_transport_authenticity_verified": false_value,
            "raw_response_authenticity_verified": false_value,
            "trusted_time_verified": false_value,
            "capacity_reserved": false_value,
            "order_placed": false_value,
            "payment_performed": false_value,
            "exactly_once_execution_verified": false_value,
            "ledger_id": digest,
            "idempotency_key": digest,
            "request_nonce": digest,
            "reconciliation_id": {"oneOf": [{"type": "null"}, digest]},
            "factory_id": slug_schema(),
            "provider": provider_schema(),
            "endpoint": endpoint_schema(),
            "reservation_challenge": digest,
            "release_subject_sha256": digest,
            "manufacturing_package": artifact_schema(),
            "intent_sha256": digest,
            "http_status": {"oneOf": [{"type": "null"}, {"type": "integer", "minimum": 100, "maximum": 599}]},
            "response_bytes": {"oneOf": [{"type": "null"}, {"type": "integer", "minimum": 1, "maximum": MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES}]},
            "response_sha256": {"oneOf": [{"type": "null"}, digest]},
            "submission_id": {"oneOf": [
                {"type": "null"},
                {"type": "string", "minLength": 1, "maxLength": MAX_SUBMISSION_ID_CHARS, "pattern": "^[^\\s\\\"\\\\]+$"}
            ]},
            "failure": {"oneOf": [
                {"type": "null"},
                {"enum": [
                    "transport_error", "response_size_invalid", "credential_reflection_detected",
                    "unexpected_http_status", "response_content_type_invalid",
                    "response_json_invalid", "response_binding_mismatch"
                ]}
            ]},
            "attempted_at_unix": {"type": "integer", "minimum": 0, "maximum": MAXIMUM_TIMESTAMP},
            "binding_sha256": digest
        }
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"})
}

fn provider_schema() -> Value {
    json!({"enum": ["jlcpcb", "pcbway", "generic"]})
}

fn endpoint_schema() -> Value {
    json!({
        "anyOf": [
            {"type": "string", "pattern": "^https://[^/?#@]+(?:/[^?#]*)?$", "maxLength": MAX_ENDPOINT_CHARS},
            {"type": "string", "pattern": "^http://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?(?:/[^?#]*)?$", "maxLength": MAX_ENDPOINT_CHARS}
        ]
    })
}

fn artifact_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["bytes", "sha256"],
        "properties": {
            "bytes": {"type": "integer", "minimum": 1, "maximum": crate::manufacturing_limits::MAX_PACKAGE_BYTES},
            "sha256": digest_schema()
        }
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
    };

    const TOKEN: &str = "test-factory-token-1482";
    const NONCE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn sample_intent(endpoint: &str, package: &[u8]) -> SignedFactoryReleaseSubmissionIntent {
        let package = FactoryReleaseArtifactIdentity {
            bytes: package.len() as u64,
            sha256: sha256(package),
        };
        let mut intent = SignedFactoryReleaseSubmissionIntent {
            schema_version: SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION,
            intent_scope: SIGNED_FACTORY_RELEASE_SUBMISSION_INTENT_SCOPE.into(),
            local_submission_intent_committed: true,
            server_side_idempotency_enforced: false,
            capacity_reserved: false,
            order_placed: false,
            payment_performed: false,
            ledger_id: "2".repeat(64),
            idempotency_key: String::new(),
            request_nonce: NONCE.into(),
            factory_id: "factory-a".into(),
            provider: FactoryProvider::Generic,
            submission_endpoint: endpoint.into(),
            reservation_challenge: "3".repeat(64),
            release_subject_sha256: "4".repeat(64),
            reservation_marker_sha256: "5".repeat(64),
            manufacturing_package: package,
            binding_sha256: String::new(),
        };
        intent.idempotency_key = domain_hash(
            IDEMPOTENCY_KEY_DOMAIN,
            &IdempotencyKeyMaterial {
                schema_version: intent.schema_version,
                ledger_id: &intent.ledger_id,
                factory_id: &intent.factory_id,
                provider: intent.provider,
                reservation_challenge: &intent.reservation_challenge,
                release_subject_sha256: &intent.release_subject_sha256,
                reservation_marker_sha256: &intent.reservation_marker_sha256,
                manufacturing_package: &intent.manufacturing_package,
            },
        )
        .unwrap();
        intent.binding_sha256 = intent_binding(&intent).unwrap();
        validate_signed_factory_release_submission_intent(&intent).unwrap();
        intent
    }

    fn acknowledgement(
        intent: &SignedFactoryReleaseSubmissionIntent,
        operation: FactoryReleaseAdapterOperation,
        reconciliation_id: Option<&str>,
        status: FactoryReleaseAdapterStatus,
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
            status,
            submission_id: "submission-1482".into(),
        })
        .unwrap()
    }

    fn serve_once(listener: TcpListener, body: Vec<u8>) -> JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            request
        })
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "client closed before request headers completed");
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
            assert!(read > 0, "client closed before request body completed");
            request.extend_from_slice(&buffer[..read]);
        }
        request.truncate(header_end + content_length);
        request
    }

    fn intent_identity(intent: &SignedFactoryReleaseSubmissionIntent) -> String {
        sha256(&render_signed_factory_release_submission_intent(intent).unwrap())
    }

    #[test]
    fn submit_posts_exact_package_and_binds_the_closed_acknowledgement() {
        let package = b"exact-manufacturing-package";
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}/submit", listener.local_addr().unwrap());
        let intent = sample_intent(&endpoint, package);
        let body = acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            FactoryReleaseAdapterStatus::AdapterAccepted,
        );
        let server = serve_once(listener, body);
        let receipt = submit_signed_factory_release_adapter(
            &intent,
            &intent_identity(&intent),
            package,
            TOKEN,
            5,
            true,
            1_700_000_000,
        )
        .unwrap();
        let request = server.join().unwrap();
        let request_text = String::from_utf8_lossy(&request);
        let request_lower = request_text.to_ascii_lowercase();
        assert!(request_text.starts_with("POST /submit HTTP/1.1\r\n"));
        assert!(request_lower.contains(&format!("idempotency-key: {}", intent.idempotency_key)));
        assert!(request_lower.contains("authorization: bearer test-factory-token-1482"));
        assert!(request.ends_with(package));
        assert_eq!(receipt.status, FactoryReleaseAdapterStatus::AdapterAccepted);
        assert!(receipt.accepted);
        assert!(receipt.manufacturing_package_transmission_attempted);
        assert!(receipt.external_submission_attempted);
        assert!(receipt.acknowledgement_validated);
        assert_eq!(receipt.submission_id.as_deref(), Some("submission-1482"));
        assert!(!receipt.trusted_time_verified);
        assert_eq!(receipt.attempted_at_unix, 1_700_000_000);
        let mut impossible_status = receipt.clone();
        impossible_status.http_status = Some(500);
        impossible_status.binding_sha256 = receipt_binding(&impossible_status).unwrap();
        assert!(
            validate_signed_factory_release_adapter_receipt(&impossible_status, Some(&intent))
                .unwrap_err()
                .contains("requires a 2xx response")
        );
        let rendered = render_signed_factory_release_adapter_receipt(&receipt).unwrap();
        assert!(
            !rendered
                .windows(TOKEN.len())
                .any(|part| part == TOKEN.as_bytes())
        );
        assert_eq!(
            parse_signed_factory_release_adapter_receipt(&rendered, &intent).unwrap(),
            receipt
        );
    }

    #[test]
    fn reconciliation_uses_get_without_retransmitting_the_package() {
        let package = b"exact-manufacturing-package";
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}/status", listener.local_addr().unwrap());
        let intent = sample_intent(&endpoint, package);
        let reconciliation_id = "6".repeat(64);
        let body = acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Reconcile,
            Some(&reconciliation_id),
            FactoryReleaseAdapterStatus::AdapterPending,
        );
        let server = serve_once(listener, body);
        let receipt = reconcile_signed_factory_release_adapter(
            &intent,
            &intent_identity(&intent),
            &endpoint,
            &reconciliation_id,
            TOKEN,
            5,
            true,
            1_700_000_001,
        )
        .unwrap();
        let request = server.join().unwrap();
        let header_end = request
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let request_text = String::from_utf8_lossy(&request);
        let request_lower = request_text.to_ascii_lowercase();
        assert!(request_text.starts_with("GET /status HTTP/1.1\r\n"));
        assert!(request_lower.contains(&format!("x-pcbex-reconciliation-id: {reconciliation_id}")));
        assert_eq!(request.len(), header_end);
        assert_eq!(receipt.status, FactoryReleaseAdapterStatus::AdapterPending);
        assert!(!receipt.accepted);
        assert!(!receipt.manufacturing_package_transmission_attempted);
        assert!(!receipt.external_submission_attempted);
        assert_eq!(
            receipt.reconciliation_id.as_deref(),
            Some(reconciliation_id.as_str())
        );
    }

    #[test]
    fn binding_mismatch_and_credential_reflection_become_bounded_unknown_receipts() {
        let package = b"exact-manufacturing-package";
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}/submit", listener.local_addr().unwrap());
        let intent = sample_intent(&endpoint, package);
        let mut body: Value = serde_json::from_slice(&acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            FactoryReleaseAdapterStatus::AdapterAccepted,
        ))
        .unwrap();
        body["request_nonce"] = Value::String("7".repeat(64));
        let server = serve_once(listener, serde_json::to_vec(&body).unwrap());
        let receipt = submit_signed_factory_release_adapter(
            &intent,
            &intent_identity(&intent),
            package,
            TOKEN,
            5,
            true,
            1_700_000_002,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(receipt.status, FactoryReleaseAdapterStatus::OutcomeUnknown);
        assert_eq!(
            receipt.failure.as_deref(),
            Some("response_binding_mismatch")
        );
        assert!(!receipt.accepted);
        let mut incomplete_identity = receipt.clone();
        incomplete_identity.response_sha256 = None;
        incomplete_identity.binding_sha256 = receipt_binding(&incomplete_identity).unwrap();
        assert!(
            validate_signed_factory_release_adapter_receipt(&incomplete_identity, Some(&intent))
                .unwrap_err()
                .contains("response identity is incomplete")
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}/submit", listener.local_addr().unwrap());
        let intent = sample_intent(&endpoint, package);
        let body = format!("{{\"message\":\"{TOKEN}\"}}").into_bytes();
        let server = serve_once(listener, body);
        let receipt = submit_signed_factory_release_adapter(
            &intent,
            &intent_identity(&intent),
            package,
            TOKEN,
            5,
            true,
            1_700_000_003,
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(
            receipt.failure.as_deref(),
            Some("credential_reflection_detected")
        );
        let rendered = render_signed_factory_release_adapter_receipt(&receipt).unwrap();
        assert!(
            !rendered
                .windows(TOKEN.len())
                .any(|part| part == TOKEN.as_bytes())
        );
    }

    #[test]
    fn canonical_inputs_bind_the_exact_intent_and_schemas_are_closed() {
        let intent = sample_intent("https://factory.example/submit", b"package");
        let raw = render_signed_factory_release_submission_intent(&intent).unwrap();
        assert_eq!(
            parse_signed_factory_release_submission_intent(&raw).unwrap(),
            intent
        );
        let compact = serde_json::to_vec(&intent).unwrap();
        assert!(
            parse_signed_factory_release_submission_intent(&compact)
                .unwrap_err()
                .contains("canonical")
        );
        assert!(
            validate_intent_sha256(&intent, &"f".repeat(64))
                .unwrap_err()
                .contains("does not match")
        );

        let mut changed_request = intent.clone();
        changed_request.request_nonce = "7".repeat(64);
        changed_request.submission_endpoint = "https://other.example/submit".into();
        changed_request.binding_sha256 = intent_binding(&changed_request).unwrap();
        validate_signed_factory_release_submission_intent(&changed_request).unwrap();
        assert_eq!(changed_request.idempotency_key, intent.idempotency_key);

        for schema in [
            signed_factory_release_submission_intent_json_schema(),
            signed_factory_release_adapter_acknowledgement_json_schema(),
            signed_factory_release_adapter_receipt_json_schema(),
        ] {
            assert_eq!(schema["type"], "object");
            assert_eq!(schema["additionalProperties"], false);
            assert!(schema["properties"].is_object());
        }
        let receipt_schema = signed_factory_release_adapter_receipt_json_schema();
        assert!(
            receipt_schema["properties"]
                .get("manufacturing_package_transmission_attempted")
                .is_some()
        );
        assert!(
            receipt_schema["properties"]
                .get("manufacturing_package_transmitted")
                .is_none()
        );
    }
}
