//! Authenticated, monotonic factory-release adapter state observations.
//!
//! This v2 HTTP Message Signatures profile leaves every v1.482 acknowledgement,
//! intent, and receipt byte unchanged. It signs three response state headers and
//! the client's accepted state head in addition to the v1.483 response context.
//! A selected durable ledger can therefore reject rollback, equivocation, gaps,
//! forks, and mutation after a terminal state. It does not establish global
//! non-equivocation, legal factory identity, trusted time, capacity, ordering,
//! payment, or server-side exactly-once execution.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory::{FactoryProvider, validate_bearer_token, validate_endpoint};
use crate::factory_release_adapter_response_authentication::{
    FactoryReleaseAdapterResponsePolicyEvidence, FactoryReleaseAdapterResponseSigner,
    capture_factory_release_adapter_response_policy,
};
use crate::policy_pack::{
    FactoryAdapterResponseAuthenticationPolicy, OrganizationPolicyPack,
    TrustedFactoryAdapterResponseKey, policy_pack_sha256, validate_policy_pack,
};
use crate::signed_factory_receipt_release_submission::{
    FactoryReleaseAdapterAcknowledgement, FactoryReleaseAdapterOperation,
    FactoryReleaseAdapterStatus, MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES,
    SIGNED_FACTORY_RELEASE_ADAPTER_ACKNOWLEDGEMENT_SCOPE,
    SIGNED_FACTORY_RELEASE_SUBMISSION_SCHEMA_VERSION, SignedFactoryReleaseAdapterReceipt,
    SignedFactoryReleaseSubmissionIntent, parse_signed_factory_release_adapter_receipt,
    receipt_from_response, render_signed_factory_release_adapter_receipt,
    render_signed_factory_release_submission_intent,
    signed_factory_release_adapter_receipt_json_schema,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use pcbex_kicad::ExactArtifactIdentity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;

pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION: u32 = 1;
pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCOPE: &str =
    "authenticated-monotonic-factory-release-adapter-state-v1";
pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_SCOPE: &str =
    "policy-pinned-authenticated-monotonic-factory-release-adapter-observation-v1";
pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE: &str =
    "pcbex-signed-factory-release-monotonic-state-response-v1";
pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_PROFILE_HEADER: &str =
    "rfc9421-ed25519-content-digest-monotonic-state-v1";
pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL: &str = "pcbex-state";
pub(crate) const FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM: &str = "ed25519";
pub(crate) const MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES: u64 = 96 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_ENTRY_BYTES: u64 = 24 * 1024;
pub(crate) const MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE: u64 = 9_999;

const STATE_DIGEST_DOMAIN: &[u8] = b"pcbex:factory-release-adapter-monotonic-state:v1\0";
const REPORT_BINDING_DOMAIN: &[u8] =
    b"pcbex:factory-release-adapter-monotonic-observation-report:v1\0";
const ENTRY_BINDING_DOMAIN: &[u8] = b"pcbex:factory-release-adapter-monotonic-state-entry:v1\0";
const MAX_SIGNATURE_TIMESTAMP: u64 = 999_999_999_999_999;
const MAX_ENDPOINT_CHARS: usize = 2048;
const MAX_SUBMISSION_ID_CHARS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterMonotonicState {
    pub(crate) schema_version: u32,
    pub(crate) state_scope: String,
    pub(crate) sequence: u64,
    pub(crate) previous_state_sha256: Option<String>,
    pub(crate) idempotency_key: String,
    pub(crate) submission_id: String,
    pub(crate) factory_id: String,
    pub(crate) provider: FactoryProvider,
    pub(crate) release_subject_sha256: String,
    pub(crate) manufacturing_package_sha256: String,
    pub(crate) status: FactoryReleaseAdapterStatus,
    pub(crate) state_sha256: String,
}

#[derive(Serialize)]
struct StateDigestMaterial<'a> {
    schema_version: u32,
    state_scope: &'a str,
    sequence: u64,
    previous_state_sha256: &'a Option<String>,
    idempotency_key: &'a str,
    submission_id: &'a str,
    factory_id: &'a str,
    provider: FactoryProvider,
    release_subject_sha256: &'a str,
    manufacturing_package_sha256: &'a str,
    status: FactoryReleaseAdapterStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterMonotonicHttpMessageSignature {
    pub(crate) profile: String,
    pub(crate) label: String,
    pub(crate) algorithm: String,
    pub(crate) key_id: String,
    pub(crate) created_at_unix: u64,
    pub(crate) expires_at_unix: u64,
    pub(crate) content_digest: String,
    pub(crate) state_sequence: String,
    pub(crate) state_previous_sha256: String,
    pub(crate) state_sha256: String,
    pub(crate) accepted_state_sequence: String,
    pub(crate) accepted_state_sha256: String,
    pub(crate) signature_input: String,
    pub(crate) signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterMonotonicObservationReport {
    pub(crate) schema_version: u32,
    pub(crate) verification_scope: String,
    pub(crate) status: String,
    pub(crate) response_authenticated: bool,
    pub(crate) response_signature_verified: bool,
    pub(crate) response_content_digest_verified: bool,
    pub(crate) policy_pack_pin_matched: bool,
    pub(crate) signer_policy_matched: bool,
    pub(crate) signature_time_active: bool,
    pub(crate) acknowledgement_authenticated: bool,
    pub(crate) state_headers_authenticated: bool,
    pub(crate) state_digest_verified: bool,
    pub(crate) request_head_bound: bool,
    pub(crate) transition_verified: bool,
    pub(crate) state_continuity_verified: bool,
    pub(crate) accepted: bool,
    pub(crate) raw_response_authenticity_verified: bool,
    pub(crate) requested_head_continuity_verified: bool,
    pub(crate) selected_ledger_state_committed: bool,
    pub(crate) global_non_equivocation_verified: bool,
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
    pub(crate) response_signature: Option<FactoryReleaseAdapterMonotonicHttpMessageSignature>,
    pub(crate) requested_state: Option<FactoryReleaseAdapterMonotonicState>,
    pub(crate) observed_state: Option<FactoryReleaseAdapterMonotonicState>,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) authentication_failure: Option<String>,
    pub(crate) continuity_failure: Option<String>,
    pub(crate) adapter_receipt: SignedFactoryReleaseAdapterReceipt,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct ReportBinding<'a> {
    schema_version: u32,
    verification_scope: &'a str,
    status: &'a str,
    response_authenticated: bool,
    response_signature_verified: bool,
    response_content_digest_verified: bool,
    policy_pack_pin_matched: bool,
    signer_policy_matched: bool,
    signature_time_active: bool,
    acknowledgement_authenticated: bool,
    state_headers_authenticated: bool,
    state_digest_verified: bool,
    request_head_bound: bool,
    transition_verified: bool,
    state_continuity_verified: bool,
    accepted: bool,
    raw_response_authenticity_verified: bool,
    requested_head_continuity_verified: bool,
    selected_ledger_state_committed: bool,
    global_non_equivocation_verified: bool,
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
    response_signature: &'a Option<FactoryReleaseAdapterMonotonicHttpMessageSignature>,
    requested_state: &'a Option<FactoryReleaseAdapterMonotonicState>,
    observed_state: &'a Option<FactoryReleaseAdapterMonotonicState>,
    evaluated_at_unix: u64,
    authentication_failure: &'a Option<String>,
    continuity_failure: &'a Option<String>,
    adapter_receipt: &'a SignedFactoryReleaseAdapterReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FactoryReleaseAdapterMonotonicStateEntry {
    pub(crate) schema_version: u32,
    pub(crate) entry_scope: String,
    pub(crate) state: FactoryReleaseAdapterMonotonicState,
    pub(crate) observation_filename: String,
    pub(crate) observation: ExactArtifactIdentity,
    pub(crate) binding_sha256: String,
}

#[derive(Serialize)]
struct EntryBinding<'a> {
    schema_version: u32,
    entry_scope: &'a str,
    state: &'a FactoryReleaseAdapterMonotonicState,
    observation_filename: &'a str,
    observation: &'a ExactArtifactIdentity,
}

#[derive(Clone, Debug, Default)]
struct CapturedResponseHeaders {
    content_type: Option<String>,
    content_digest: Option<String>,
    state_sequence: Option<String>,
    state_previous_sha256: Option<String>,
    state_sha256: Option<String>,
    signature_input: Option<String>,
    signature: Option<String>,
    failure: Option<&'static str>,
}

#[derive(Clone, Copy)]
struct StateHeaderValues<'a> {
    sequence: &'a str,
    previous_sha256: &'a str,
    state_sha256: &'a str,
}

pub(crate) fn build_factory_release_adapter_monotonic_state(
    intent: &SignedFactoryReleaseSubmissionIntent,
    sequence: u64,
    previous_state_sha256: Option<&str>,
    status: FactoryReleaseAdapterStatus,
    submission_id: &str,
) -> Result<FactoryReleaseAdapterMonotonicState, String> {
    let mut state = FactoryReleaseAdapterMonotonicState {
        schema_version: FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION,
        state_scope: FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCOPE.into(),
        sequence,
        previous_state_sha256: previous_state_sha256.map(str::to_owned),
        idempotency_key: intent.idempotency_key.clone(),
        submission_id: submission_id.into(),
        factory_id: intent.factory_id.clone(),
        provider: intent.provider,
        release_subject_sha256: intent.release_subject_sha256.clone(),
        manufacturing_package_sha256: intent.manufacturing_package.sha256.clone(),
        status,
        state_sha256: String::new(),
    };
    state.state_sha256 = state_digest(&state)?;
    validate_monotonic_state(&state, intent)?;
    Ok(state)
}

pub(crate) fn validate_factory_release_adapter_state_transition(
    requested: Option<&FactoryReleaseAdapterMonotonicState>,
    observed: &FactoryReleaseAdapterMonotonicState,
) -> Result<(), &'static str> {
    let Some(requested) = requested else {
        if observed.sequence != 0 || observed.previous_state_sha256.is_some() {
            return Err("state_chain_genesis_required");
        }
        return Ok(());
    };
    if observed.idempotency_key != requested.idempotency_key
        || observed.factory_id != requested.factory_id
        || observed.provider != requested.provider
        || observed.release_subject_sha256 != requested.release_subject_sha256
        || observed.manufacturing_package_sha256 != requested.manufacturing_package_sha256
    {
        return Err("state_subject_changed");
    }
    if observed.sequence < requested.sequence {
        return Err("state_rollback_detected");
    }
    if observed.sequence == requested.sequence {
        if observed.state_sha256 != requested.state_sha256 || observed != requested {
            return Err("state_equivocation_detected");
        }
        return Ok(());
    }
    if observed.sequence > requested.sequence + 1 {
        return Err("state_sequence_gap_detected");
    }
    if observed.previous_state_sha256.as_deref() != Some(requested.state_sha256.as_str()) {
        return Err("state_fork_detected");
    }
    if matches!(
        requested.status,
        FactoryReleaseAdapterStatus::AdapterAccepted | FactoryReleaseAdapterStatus::AdapterRejected
    ) {
        return Err("terminal_state_mutation_detected");
    }
    if observed.submission_id != requested.submission_id {
        return Err("submission_identity_changed");
    }
    Ok(())
}

pub(crate) fn render_factory_release_adapter_monotonic_observation_report(
    report: &FactoryReleaseAdapterMonotonicObservationReport,
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy_source: &[u8],
    expected_policy_sha256: &str,
) -> Result<Vec<u8>, String> {
    let (_, policy) =
        capture_factory_release_adapter_response_policy(policy_source, expected_policy_sha256)?;
    validate_monotonic_report(
        report,
        intent,
        &policy,
        policy_source,
        expected_policy_sha256,
    )?;
    render_bounded(
        report,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES,
        "factory release adapter monotonic observation report",
    )
}

pub(crate) fn parse_factory_release_adapter_monotonic_observation_report(
    source: &[u8],
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy_source: &[u8],
    expected_policy_sha256: &str,
) -> Result<FactoryReleaseAdapterMonotonicObservationReport, String> {
    let report = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES,
        "factory release adapter monotonic observation report",
    )?;
    let (_, policy) =
        capture_factory_release_adapter_response_policy(policy_source, expected_policy_sha256)?;
    validate_monotonic_report(
        &report,
        intent,
        &policy,
        policy_source,
        expected_policy_sha256,
    )?;
    Ok(report)
}

pub(crate) fn build_factory_release_adapter_monotonic_state_entry(
    state: &FactoryReleaseAdapterMonotonicState,
    observation_filename: &str,
    observation_source: &[u8],
) -> Result<FactoryReleaseAdapterMonotonicStateEntry, String> {
    validate_observation_filename(observation_filename)?;
    if observation_source.is_empty()
        || observation_source.len() as u64 > MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES
    {
        return Err("monotonic observation source is outside its bound".into());
    }
    let mut entry = FactoryReleaseAdapterMonotonicStateEntry {
        schema_version: FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION,
        entry_scope: "durable-authenticated-factory-release-monotonic-state-entry-v1".into(),
        state: state.clone(),
        observation_filename: observation_filename.into(),
        observation: exact_identity(observation_source),
        binding_sha256: String::new(),
    };
    entry.binding_sha256 = entry_binding(&entry)?;
    validate_monotonic_state_entry(&entry)?;
    Ok(entry)
}

pub(crate) fn render_factory_release_adapter_monotonic_state_entry(
    entry: &FactoryReleaseAdapterMonotonicStateEntry,
) -> Result<Vec<u8>, String> {
    validate_monotonic_state_entry(entry)?;
    render_bounded(
        entry,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_ENTRY_BYTES,
        "factory release adapter monotonic state entry",
    )
}

pub(crate) fn parse_factory_release_adapter_monotonic_state_entry(
    source: &[u8],
) -> Result<FactoryReleaseAdapterMonotonicStateEntry, String> {
    let entry = parse_canonical(
        source,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_ENTRY_BYTES,
        "factory release adapter monotonic state entry",
    )?;
    validate_monotonic_state_entry(&entry)?;
    Ok(entry)
}

pub(crate) fn monotonic_factory_release_submission_filename(
    idempotency_key: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    Ok(format!(
        "monotonic-factory-release-submission-v1-{idempotency_key}.json"
    ))
}

pub(crate) fn monotonic_factory_release_reconciliation_filename(
    idempotency_key: &str,
    reconciliation_id: &str,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    validate_digest(reconciliation_id, "factory release reconciliation id")?;
    Ok(format!(
        "monotonic-factory-release-reconciliation-v1-{idempotency_key}-{reconciliation_id}.json"
    ))
}

pub(crate) fn monotonic_factory_release_state_filename(
    idempotency_key: &str,
    sequence: u64,
) -> Result<String, String> {
    validate_digest(idempotency_key, "factory release idempotency key")?;
    if sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE {
        return Err("factory release adapter state sequence exceeds its bound".into());
    }
    Ok(format!(
        "monotonic-factory-release-state-v1-{idempotency_key}-{sequence:04}.json"
    ))
}

/// Production-compiled reference signer for adapter conformance harnesses.
///
/// The secret key is consumed only in memory and is never retained in the
/// returned evidence or included in errors.
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn sign_factory_release_adapter_monotonic_http_response(
    intent: &SignedFactoryReleaseSubmissionIntent,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    endpoint: &str,
    http_status: u16,
    response_body: &[u8],
    requested_state: Option<&FactoryReleaseAdapterMonotonicState>,
    observed_state: &FactoryReleaseAdapterMonotonicState,
    policy: &OrganizationPolicyPack,
    key_id: &str,
    secret_key: &[u8; 32],
    created_at_unix: u64,
    expires_at_unix: u64,
) -> Result<FactoryReleaseAdapterMonotonicHttpMessageSignature, String> {
    validate_signature_context(intent, operation, reconciliation_id, endpoint)?;
    if !(100..=599).contains(&http_status) {
        return Err("factory adapter response HTTP status is outside its bound".into());
    }
    if response_body.is_empty()
        || response_body.len() as u64 > MAX_SIGNED_FACTORY_RELEASE_ADAPTER_RESPONSE_BYTES
    {
        return Err("factory adapter response body is outside its bound".into());
    }
    validate_monotonic_state(observed_state, intent)?;
    if let Some(requested) = requested_state {
        validate_monotonic_state(requested, intent)?;
    }
    validate_factory_release_adapter_state_transition(requested_state, observed_state)
        .map_err(str::to_owned)?;
    validate_acknowledgement_body(
        response_body,
        intent,
        operation,
        reconciliation_id,
        observed_state,
    )?;
    let trusted = trusted_response_key(policy, key_id)?;
    validate_trusted_response_key_binding(trusted, intent)?;
    validate_signature_window(
        created_at_unix,
        expires_at_unix,
        response_policy(policy)?,
        None,
    )?;
    let signing_key = SigningKey::from_bytes(secret_key);
    if hex::encode(signing_key.verifying_key().to_bytes()) != trusted.public_key {
        return Err("factory adapter response private key does not match its policy key".into());
    }
    let content_digest = content_digest(response_body);
    let state_sequence = observed_state.sequence.to_string();
    let state_previous_sha256 = observed_state
        .previous_state_sha256
        .clone()
        .unwrap_or_else(|| "none".into());
    let (accepted_state_sequence, accepted_state_sha256) = request_head_values(requested_state);
    let signature_input = signature_input(operation, created_at_unix, expires_at_unix, key_id);
    let state_headers = StateHeaderValues {
        sequence: &state_sequence,
        previous_sha256: &state_previous_sha256,
        state_sha256: &observed_state.state_sha256,
    };
    let base = signature_base(
        intent,
        operation,
        reconciliation_id,
        endpoint,
        http_status,
        &content_digest,
        state_headers,
        requested_state,
        &signature_input,
    )?;
    let signature_bytes = signing_key.sign(base.as_bytes()).to_bytes();
    let evidence = FactoryReleaseAdapterMonotonicHttpMessageSignature {
        profile: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE.into(),
        label: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL.into(),
        algorithm: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.into(),
        created_at_unix,
        expires_at_unix,
        content_digest,
        state_sequence,
        state_previous_sha256,
        state_sha256: observed_state.state_sha256.clone(),
        accepted_state_sequence,
        accepted_state_sha256,
        signature_input,
        signature: format!(
            "{}=:{}:",
            FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL,
            STANDARD.encode(signature_bytes)
        ),
    };
    validate_signature_evidence_shape(&evidence, operation)?;
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn submit_monotonic_factory_release_adapter(
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
        FactoryReleaseAdapterMonotonicObservationReport,
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
            FACTORY_RELEASE_ADAPTER_MONOTONIC_PROFILE_HEADER,
        )
        .header("X-PCBEX-Accepted-State-Sequence", "none")
        .header("X-PCBEX-Accepted-State-SHA256", "none")
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
        None,
        bearer_token,
        attempted_at_unix,
        policy_evidence,
        policy,
        response,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn reconcile_monotonic_factory_release_adapter(
    intent: &SignedFactoryReleaseSubmissionIntent,
    intent_sha256: &str,
    endpoint: &str,
    reconciliation_id: &str,
    requested_state: Option<&FactoryReleaseAdapterMonotonicState>,
    bearer_token: &str,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    attempted_at_unix: u64,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
) -> Result<
    (
        SignedFactoryReleaseAdapterReceipt,
        FactoryReleaseAdapterMonotonicObservationReport,
    ),
    String,
> {
    validate_digest(reconciliation_id, "factory release reconciliation id")?;
    if let Some(requested) = requested_state {
        validate_monotonic_state(requested, intent)?;
    }
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
    let (accepted_sequence, accepted_sha256) = request_head_values(requested_state);
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
            FACTORY_RELEASE_ADAPTER_MONOTONIC_PROFILE_HEADER,
        )
        .header("X-PCBEX-Accepted-State-Sequence", &accepted_sequence)
        .header("X-PCBEX-Accepted-State-SHA256", &accepted_sha256)
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
        requested_state,
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
    requested_state: Option<&FactoryReleaseAdapterMonotonicState>,
    bearer_token: &str,
    attempted_at_unix: u64,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<
    (
        SignedFactoryReleaseAdapterReceipt,
        FactoryReleaseAdapterMonotonicObservationReport,
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
        requested_state,
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
    requested_state: Option<&FactoryReleaseAdapterMonotonicState>,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    policy: &OrganizationPolicyPack,
    headers: &CapturedResponseHeaders,
    evaluated_at_unix: u64,
) -> Result<FactoryReleaseAdapterMonotonicObservationReport, String> {
    validate_timestamp(evaluated_at_unix, "adapter response evaluation timestamp")?;
    let intent_source = render_signed_factory_release_submission_intent(intent)?;
    if sha256(&intent_source) != intent_sha256 {
        return Err("factory release submission intent SHA-256 does not match its bytes".into());
    }
    let receipt_source = render_signed_factory_release_adapter_receipt(receipt)?;
    parse_signed_factory_release_adapter_receipt(&receipt_source, intent)?;
    let receipt_sha256 = sha256(&receipt_source);
    validate_policy_evidence_without_source(policy_evidence, policy)?;
    if let Some(requested) = requested_state {
        validate_monotonic_state(requested, intent)?;
    }

    let negative = |failure: &str| {
        build_monotonic_report(
            intent_sha256,
            &receipt_sha256,
            receipt,
            policy_evidence,
            None,
            None,
            requested_state.cloned(),
            None,
            evaluated_at_unix,
            Some(failure),
            None,
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
    let content_type = required_header(&headers.content_type, "captured response content type")?;
    let content_digest_value =
        required_header(&headers.content_digest, "captured response content digest")?;
    let state_sequence_value =
        required_header(&headers.state_sequence, "captured response state sequence")?;
    let state_previous_value = required_header(
        &headers.state_previous_sha256,
        "captured response state predecessor",
    )?;
    let state_sha256_value =
        required_header(&headers.state_sha256, "captured response state digest")?;
    let signature_input_value = required_header(
        &headers.signature_input,
        "captured response signature input",
    )?;
    let signature_value = required_header(&headers.signature, "captured response signature")?;
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
    let sequence = match parse_state_sequence(state_sequence_value) {
        Ok(sequence) => sequence,
        Err(_) => return negative("response_state_headers_invalid"),
    };
    let previous_state_sha256 = match parse_optional_state_digest(state_previous_value) {
        Ok(value) => value,
        Err(_) => return negative("response_state_headers_invalid"),
    };
    if validate_digest(state_sha256_value, "factory release adapter state SHA-256").is_err() {
        return negative("response_state_headers_invalid");
    }
    if (sequence == 0) != previous_state_sha256.is_none() {
        return negative("response_state_headers_invalid");
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
    let state_headers = StateHeaderValues {
        sequence: state_sequence_value,
        previous_sha256: state_previous_value,
        state_sha256: state_sha256_value,
    };
    let base = match signature_base(
        intent,
        receipt.operation,
        receipt.reconciliation_id.as_deref(),
        &receipt.endpoint,
        receipt.http_status.unwrap_or(0),
        content_digest_value,
        state_headers,
        requested_state,
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

    let (accepted_state_sequence, accepted_state_sha256) = request_head_values(requested_state);
    let evidence = FactoryReleaseAdapterMonotonicHttpMessageSignature {
        profile: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE.into(),
        label: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL.into(),
        algorithm: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM.into(),
        key_id: key_id.clone(),
        created_at_unix,
        expires_at_unix,
        content_digest: content_digest_value.into(),
        state_sequence: state_sequence_value.into(),
        state_previous_sha256: state_previous_value.into(),
        state_sha256: state_sha256_value.into(),
        accepted_state_sequence,
        accepted_state_sha256,
        signature_input: signature_input_value.into(),
        signature: signature_value.into(),
    };
    let signer = FactoryReleaseAdapterResponseSigner {
        key_id,
        factory_id: trusted.factory_id.clone(),
        provider: receipt.provider,
        public_key: trusted.public_key.clone(),
    };

    let (observed_state, continuity_failure) = if !receipt.acknowledgement_validated {
        (None, Some("acknowledgement_not_authenticated"))
    } else {
        let submission_id = receipt.submission_id.as_deref().ok_or_else(|| {
            "validated factory release acknowledgement has no submission id".to_string()
        })?;
        let state = build_factory_release_adapter_monotonic_state(
            intent,
            sequence,
            previous_state_sha256.as_deref(),
            receipt.status,
            submission_id,
        )?;
        let failure = if state.state_sha256 != state_sha256_value {
            Some("state_digest_mismatch")
        } else {
            validate_factory_release_adapter_state_transition(requested_state, &state).err()
        };
        (Some(state), failure)
    };
    build_monotonic_report(
        intent_sha256,
        &receipt_sha256,
        receipt,
        policy_evidence,
        Some(signer),
        Some(evidence),
        requested_state.cloned(),
        observed_state,
        evaluated_at_unix,
        None,
        continuity_failure,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_monotonic_report(
    intent_sha256: &str,
    receipt_sha256: &str,
    receipt: &SignedFactoryReleaseAdapterReceipt,
    policy_evidence: &FactoryReleaseAdapterResponsePolicyEvidence,
    signer: Option<FactoryReleaseAdapterResponseSigner>,
    response_signature: Option<FactoryReleaseAdapterMonotonicHttpMessageSignature>,
    requested_state: Option<FactoryReleaseAdapterMonotonicState>,
    observed_state: Option<FactoryReleaseAdapterMonotonicState>,
    evaluated_at_unix: u64,
    authentication_failure: Option<&str>,
    continuity_failure: Option<&str>,
) -> Result<FactoryReleaseAdapterMonotonicObservationReport, String> {
    let authenticated = authentication_failure.is_none();
    let acknowledgement_authenticated = authenticated && receipt.acknowledgement_validated;
    let state_digest_verified = authenticated
        && observed_state.as_ref().is_some_and(|state| {
            response_signature
                .as_ref()
                .is_some_and(|signature| signature.state_sha256 == state.state_sha256)
        });
    let transition_verified = state_digest_verified && continuity_failure.is_none();
    let continuity_verified = authenticated
        && acknowledgement_authenticated
        && state_digest_verified
        && transition_verified;
    let mut report = FactoryReleaseAdapterMonotonicObservationReport {
        schema_version: FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION,
        verification_scope: FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_SCOPE.into(),
        status: if continuity_verified {
            "state_continuity_verified"
        } else {
            "state_continuity_not_verified"
        }
        .into(),
        response_authenticated: authenticated,
        response_signature_verified: authenticated,
        response_content_digest_verified: authenticated,
        policy_pack_pin_matched: true,
        signer_policy_matched: authenticated,
        signature_time_active: authenticated,
        acknowledgement_authenticated,
        state_headers_authenticated: authenticated,
        state_digest_verified,
        request_head_bound: authenticated,
        transition_verified,
        state_continuity_verified: continuity_verified,
        accepted: continuity_verified && receipt.accepted,
        raw_response_authenticity_verified: authenticated,
        requested_head_continuity_verified: continuity_verified,
        selected_ledger_state_committed: false,
        global_non_equivocation_verified: false,
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
        requested_state,
        observed_state,
        evaluated_at_unix,
        authentication_failure: authentication_failure.map(str::to_owned),
        continuity_failure: continuity_failure.map(str::to_owned),
        adapter_receipt: receipt.clone(),
        binding_sha256: String::new(),
    };
    report.binding_sha256 = report_binding(&report)?;
    Ok(report)
}

fn validate_monotonic_report(
    report: &FactoryReleaseAdapterMonotonicObservationReport,
    intent: &SignedFactoryReleaseSubmissionIntent,
    policy: &OrganizationPolicyPack,
    policy_source: &[u8],
    expected_policy_sha256: &str,
) -> Result<(), String> {
    if report.schema_version != FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION
        || report.verification_scope != FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_SCOPE
        || !report.policy_pack_pin_matched
        || report.global_non_equivocation_verified
        || report.selected_ledger_state_committed
        || report.endpoint_transport_authenticity_verified
        || report.factory_legal_identity_verified
        || report.trusted_time_verified
        || report.server_side_idempotency_enforced
        || report.capacity_reserved
        || report.order_placed
        || report.payment_performed
        || report.exactly_once_execution_verified
    {
        return Err("factory adapter monotonic report identity or nonclaims are invalid".into());
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
        "factory release adapter monotonic report binding SHA-256",
    )?;
    let intent_source = render_signed_factory_release_submission_intent(intent)?;
    if sha256(&intent_source) != report.intent_sha256 {
        return Err("monotonic observation report does not bind the exact intent".into());
    }
    let receipt_source = render_signed_factory_release_adapter_receipt(&report.adapter_receipt)?;
    parse_signed_factory_release_adapter_receipt(&receipt_source, intent)?;
    if sha256(&receipt_source) != report.adapter_receipt_sha256 {
        return Err("monotonic observation report does not bind the exact receipt".into());
    }
    let (captured_evidence, captured_policy) =
        capture_factory_release_adapter_response_policy(policy_source, expected_policy_sha256)?;
    if captured_policy != *policy || captured_evidence != report.policy_pack {
        return Err("monotonic observation report policy evidence is invalid".into());
    }
    if let Some(requested) = &report.requested_state {
        validate_monotonic_state(requested, intent)?;
    }

    let authenticated = report.response_authenticated;
    if report.response_signature_verified != authenticated
        || report.response_content_digest_verified != authenticated
        || report.signer_policy_matched != authenticated
        || report.signature_time_active != authenticated
        || report.state_headers_authenticated != authenticated
        || report.request_head_bound != authenticated
        || report.raw_response_authenticity_verified != authenticated
        || report.signer.is_some() != authenticated
        || report.response_signature.is_some() != authenticated
        || report.authentication_failure.is_some() == authenticated
        || report.acknowledgement_authenticated
            != (authenticated && report.adapter_receipt.acknowledgement_validated)
    {
        return Err("factory adapter monotonic response-authentication flags are invalid".into());
    }

    if authenticated {
        verify_authenticated_report(report, intent, policy)?;
    } else {
        validate_authentication_failure(
            report
                .authentication_failure
                .as_deref()
                .expect("negative authentication report has a failure"),
        )?;
        if report.observed_state.is_some()
            || report.state_digest_verified
            || report.transition_verified
            || report.state_continuity_verified
            || report.requested_head_continuity_verified
            || report.accepted
            || report.continuity_failure.is_some()
        {
            return Err("unauthenticated monotonic report contains positive state evidence".into());
        }
    }

    let expected_continuity_failure = if !authenticated {
        None
    } else if !report.adapter_receipt.acknowledgement_validated {
        Some("acknowledgement_not_authenticated")
    } else {
        let observed = report.observed_state.as_ref().ok_or_else(|| {
            "authenticated acknowledgement has no observed monotonic state".to_string()
        })?;
        if report
            .response_signature
            .as_ref()
            .expect("authenticated signature exists")
            .state_sha256
            != observed.state_sha256
        {
            Some("state_digest_mismatch")
        } else {
            validate_factory_release_adapter_state_transition(
                report.requested_state.as_ref(),
                observed,
            )
            .err()
        }
    };
    if report.continuity_failure.as_deref() != expected_continuity_failure {
        return Err("factory adapter monotonic continuity failure is invalid".into());
    }
    if let Some(failure) = report.continuity_failure.as_deref() {
        validate_continuity_failure(failure)?;
    }
    let state_digest_verified = authenticated
        && report.observed_state.as_ref().is_some_and(|state| {
            report
                .response_signature
                .as_ref()
                .is_some_and(|signature| signature.state_sha256 == state.state_sha256)
        });
    let transition_verified = state_digest_verified && expected_continuity_failure.is_none();
    let continuity_verified = authenticated
        && report.adapter_receipt.acknowledgement_validated
        && state_digest_verified
        && transition_verified;
    if report.state_digest_verified != state_digest_verified
        || report.transition_verified != transition_verified
        || report.state_continuity_verified != continuity_verified
        || report.requested_head_continuity_verified != continuity_verified
        || report.accepted != (continuity_verified && report.adapter_receipt.accepted)
        || report.status
            != if continuity_verified {
                "state_continuity_verified"
            } else {
                "state_continuity_not_verified"
            }
    {
        return Err("factory adapter monotonic continuity flags are invalid".into());
    }
    if report.binding_sha256 != report_binding(report)? {
        return Err("factory adapter monotonic report binding is invalid".into());
    }
    Ok(())
}

fn verify_authenticated_report(
    report: &FactoryReleaseAdapterMonotonicObservationReport,
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
        return Err("monotonic response signer does not match its pinned policy key".into());
    }
    let response_sha256 = report
        .adapter_receipt
        .response_sha256
        .as_deref()
        .ok_or_else(|| "authenticated response has no response body identity".to_string())?;
    if hex::encode(parse_content_digest(&evidence.content_digest)?) != response_sha256 {
        return Err("authenticated response Content-Digest does not match its body".into());
    }
    let expected_head = request_head_values(report.requested_state.as_ref());
    if (
        evidence.accepted_state_sequence.as_str(),
        evidence.accepted_state_sha256.as_str(),
    ) != (expected_head.0.as_str(), expected_head.1.as_str())
    {
        return Err("authenticated response does not bind the selected accepted state head".into());
    }
    validate_signature_window(
        evidence.created_at_unix,
        evidence.expires_at_unix,
        response_policy(policy)?,
        Some(report.evaluated_at_unix),
    )?;
    let state_headers = StateHeaderValues {
        sequence: &evidence.state_sequence,
        previous_sha256: &evidence.state_previous_sha256,
        state_sha256: &evidence.state_sha256,
    };
    let base = signature_base(
        intent,
        report.adapter_receipt.operation,
        report.adapter_receipt.reconciliation_id.as_deref(),
        &report.adapter_receipt.endpoint,
        report.adapter_receipt.http_status.ok_or_else(|| {
            "authenticated factory adapter response has no HTTP status".to_string()
        })?,
        &evidence.content_digest,
        state_headers,
        report.requested_state.as_ref(),
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
        .map_err(|error| {
            format!("invalid factory adapter monotonic response signature: {error}")
        })?;
    if let Some(observed) = &report.observed_state {
        validate_monotonic_state(observed, intent)?;
        if observed.sequence.to_string() != evidence.state_sequence
            || observed.previous_state_sha256.as_deref().unwrap_or("none")
                != evidence.state_previous_sha256
        {
            return Err("observed state does not match authenticated state headers".into());
        }
        if report.adapter_receipt.submission_id.as_deref() != Some(&observed.submission_id)
            || report.adapter_receipt.status != observed.status
        {
            return Err("observed state does not match authenticated acknowledgement".into());
        }
    } else if report.adapter_receipt.acknowledgement_validated {
        return Err("authenticated acknowledgement has no observed state".into());
    }
    Ok(())
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
        "x-pcbex-state-sequence",
        "x-pcbex-state-previous-sha256",
        "x-pcbex-state-sha256",
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
            "x-pcbex-state-sequence" => captured.state_sequence = Some(value),
            "x-pcbex-state-previous-sha256" => captured.state_previous_sha256 = Some(value),
            "x-pcbex-state-sha256" => captured.state_sha256 = Some(value),
            "signature-input" => captured.signature_input = Some(value),
            "signature" => captured.signature = Some(value),
            _ => unreachable!("fixed monotonic response header"),
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

fn required_header<'a>(value: &'a Option<String>, label: &str) -> Result<&'a str, String> {
    value
        .as_deref()
        .ok_or_else(|| format!("{label} is missing"))
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
            "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-state-sequence\" \"x-pcbex-state-previous-sha256\" \"x-pcbex-state-sha256\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"x-pcbex-accepted-state-sequence\";req \"x-pcbex-accepted-state-sha256\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
        }
        FactoryReleaseAdapterOperation::Reconcile => {
            "(\"@status\" \"content-digest\" \"content-type\" \"x-pcbex-state-sequence\" \"x-pcbex-state-previous-sha256\" \"x-pcbex-state-sha256\" \"x-pcbex-adapter\";req \"x-pcbex-schema-version\";req \"x-pcbex-response-signature-profile\";req \"x-pcbex-accepted-state-sequence\";req \"x-pcbex-accepted-state-sha256\";req \"idempotency-key\";req \"x-pcbex-request-nonce\";req \"x-pcbex-reconciliation-id\";req \"x-pcbex-release-subject-sha256\";req \"x-pcbex-package-sha256\";req \"x-pcbex-factory-id\";req \"@method\";req \"@target-uri\";req)"
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
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL,
        signature_components(operation),
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM,
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE,
    )
}

fn parse_signature_input(
    value: &str,
    operation: FactoryReleaseAdapterOperation,
) -> Result<(u64, u64, String), String> {
    let prefix = format!(
        "{}={};created=",
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL,
        signature_components(operation)
    );
    let rest = value.strip_prefix(&prefix).ok_or_else(|| {
        "factory adapter monotonic Signature-Input profile is invalid".to_string()
    })?;
    let (created, rest) = rest
        .split_once(";expires=")
        .ok_or_else(|| "factory adapter monotonic Signature-Input has no expires".to_string())?;
    let (expires, rest) = rest
        .split_once(";keyid=\"")
        .ok_or_else(|| "factory adapter monotonic Signature-Input has no keyid".to_string())?;
    let suffix = format!(
        "\";alg=\"{}\";tag=\"{}\"",
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM,
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE
    );
    let key_id = rest
        .strip_suffix(&suffix)
        .ok_or_else(|| "factory adapter monotonic Signature-Input suffix is invalid".to_string())?;
    validate_slug(key_id, "factory adapter response key id")?;
    let created = parse_structured_timestamp(created, "signature created")?;
    let expires = parse_structured_timestamp(expires, "signature expires")?;
    if value != signature_input(operation, created, expires, key_id) {
        return Err("factory adapter monotonic Signature-Input is not canonical".into());
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
    state_headers: StateHeaderValues<'_>,
    requested_state: Option<&FactoryReleaseAdapterMonotonicState>,
    signature_input: &str,
) -> Result<String, String> {
    validate_signature_context(intent, operation, reconciliation_id, endpoint)?;
    if !(100..=599).contains(&http_status) {
        return Err("factory adapter response HTTP status is outside its bound".into());
    }
    parse_content_digest(content_digest)?;
    let sequence = parse_state_sequence(state_headers.sequence)?;
    let previous = parse_optional_state_digest(state_headers.previous_sha256)?;
    validate_digest(
        state_headers.state_sha256,
        "factory release adapter state SHA-256",
    )?;
    if (sequence == 0) != previous.is_none() {
        return Err("factory adapter response state predecessor shape is invalid".into());
    }
    if let Some(requested) = requested_state {
        validate_monotonic_state(requested, intent)?;
    }
    let (created, expires, key_id) = parse_signature_input(signature_input, operation)?;
    let parameters = signature_input
        .strip_prefix(&format!(
            "{}=",
            FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL
        ))
        .ok_or_else(|| "factory adapter response Signature-Input label is invalid".to_string())?;
    if parameters != signature_input_for_parameters(operation, created, expires, &key_id) {
        return Err("factory adapter response signature parameters are invalid".into());
    }
    let (accepted_sequence, accepted_sha256) = request_head_values(requested_state);
    let method = match operation {
        FactoryReleaseAdapterOperation::Submit => "POST",
        FactoryReleaseAdapterOperation::Reconcile => "GET",
    };
    let mut lines = vec![
        format!("\"@status\": {http_status}"),
        format!("\"content-digest\": {content_digest}"),
        "\"content-type\": application/json".into(),
        format!("\"x-pcbex-state-sequence\": {}", state_headers.sequence),
        format!(
            "\"x-pcbex-state-previous-sha256\": {}",
            state_headers.previous_sha256
        ),
        format!("\"x-pcbex-state-sha256\": {}", state_headers.state_sha256),
        "\"x-pcbex-adapter\";req: signed-factory-release-http-v1".into(),
        "\"x-pcbex-schema-version\";req: 1".into(),
        format!(
            "\"x-pcbex-response-signature-profile\";req: {}",
            FACTORY_RELEASE_ADAPTER_MONOTONIC_PROFILE_HEADER
        ),
        format!("\"x-pcbex-accepted-state-sequence\";req: {accepted_sequence}"),
        format!("\"x-pcbex-accepted-state-sha256\";req: {accepted_sha256}"),
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
            FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL
        ))
        .expect("fixed signature label")
        .into()
}

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
    let prefix = format!("{}=:", FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL);
    let encoded = value
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(':'))
        .ok_or_else(|| "factory adapter monotonic Signature profile is invalid".to_string())?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|error| format!("invalid factory adapter monotonic Signature: {error}"))?;
    let signature: [u8; 64] = decoded
        .try_into()
        .map_err(|_| "factory adapter monotonic Signature is not Ed25519".to_string())?;
    if format!(
        "{}=:{}:",
        FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL,
        STANDARD.encode(signature)
    ) != value
    {
        return Err("factory adapter monotonic Signature is not canonical".into());
    }
    Ok(signature)
}

fn parse_structured_timestamp(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("factory adapter response {label} is not canonical"));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| format!("factory adapter response {label} is invalid"))?;
    validate_timestamp(value, label)?;
    Ok(value)
}

fn validate_signature_window(
    created: u64,
    expires: u64,
    policy: &FactoryAdapterResponseAuthenticationPolicy,
    evaluated_at: Option<u64>,
) -> Result<(), String> {
    validate_timestamp(created, "signature created")?;
    validate_timestamp(expires, "signature expires")?;
    if expires <= created {
        return Err("factory adapter response signature window is empty".into());
    }
    if expires - created > policy.maximum_validity_seconds {
        return Err("factory adapter response signature window exceeds policy".into());
    }
    if let Some(evaluated_at) = evaluated_at {
        validate_timestamp(evaluated_at, "signature evaluation")?;
        if evaluated_at < created || evaluated_at > expires {
            return Err("factory adapter response signature is not active".into());
        }
    }
    Ok(())
}

fn validate_signature_evidence_shape(
    evidence: &FactoryReleaseAdapterMonotonicHttpMessageSignature,
    operation: FactoryReleaseAdapterOperation,
) -> Result<(), String> {
    if evidence.profile != FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE
        || evidence.label != FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL
        || evidence.algorithm != FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM
    {
        return Err("factory adapter monotonic signature evidence profile is invalid".into());
    }
    validate_slug(&evidence.key_id, "factory adapter response key id")?;
    parse_content_digest(&evidence.content_digest)?;
    let sequence = parse_state_sequence(&evidence.state_sequence)?;
    let previous = parse_optional_state_digest(&evidence.state_previous_sha256)?;
    if (sequence == 0) != previous.is_none() {
        return Err("factory adapter monotonic state header shape is invalid".into());
    }
    validate_digest(&evidence.state_sha256, "factory adapter state SHA-256")?;
    validate_request_head_values(
        &evidence.accepted_state_sequence,
        &evidence.accepted_state_sha256,
    )?;
    let (created, expires, key_id) = parse_signature_input(&evidence.signature_input, operation)?;
    if created != evidence.created_at_unix
        || expires != evidence.expires_at_unix
        || key_id != evidence.key_id
    {
        return Err("factory adapter monotonic signature evidence parameters differ".into());
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
            "organization policy has no factory adapter response authentication policy".into()
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
        .ok_or_else(|| "factory adapter response key is not trusted".into())
}

fn validate_trusted_response_key_binding(
    trusted: &TrustedFactoryAdapterResponseKey,
    intent: &SignedFactoryReleaseSubmissionIntent,
) -> Result<(), String> {
    if trusted.factory_id != intent.factory_id || trusted.provider != provider_name(intent.provider)
    {
        return Err("factory adapter response key does not match the selected factory".into());
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
        crate::fabrication_authorization::MAX_POLICY_PACK_BYTES,
        "factory adapter response policy source",
    )?;
    validate_digest(
        &evidence.canonical_sha256,
        "factory adapter response policy canonical SHA-256",
    )?;
    validate_slug(&evidence.id, "factory adapter response policy id")?;
    if evidence.revision == 0
        || evidence.id != policy.id
        || evidence.revision != policy.revision
        || evidence.canonical_sha256 != policy_pack_sha256(policy)?
    {
        return Err("factory adapter response policy evidence is invalid".into());
    }
    Ok(())
}

fn validate_monotonic_state(
    state: &FactoryReleaseAdapterMonotonicState,
    intent: &SignedFactoryReleaseSubmissionIntent,
) -> Result<(), String> {
    render_signed_factory_release_submission_intent(intent)?;
    validate_monotonic_state_shape(state)?;
    if state.idempotency_key != intent.idempotency_key
        || state.factory_id != intent.factory_id
        || state.provider != intent.provider
        || state.release_subject_sha256 != intent.release_subject_sha256
        || state.manufacturing_package_sha256 != intent.manufacturing_package.sha256
    {
        return Err("factory release adapter monotonic state identity is invalid".into());
    }
    Ok(())
}

fn validate_monotonic_state_shape(
    state: &FactoryReleaseAdapterMonotonicState,
) -> Result<(), String> {
    if state.schema_version != FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION
        || state.state_scope != FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCOPE
        || state.sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE
    {
        return Err("factory release adapter monotonic state shape is invalid".into());
    }
    if (state.sequence == 0) != state.previous_state_sha256.is_none() {
        return Err("factory release adapter state predecessor shape is invalid".into());
    }
    if let Some(previous) = &state.previous_state_sha256 {
        validate_digest(previous, "factory release adapter previous state SHA-256")?;
    }
    validate_digest(&state.idempotency_key, "factory release idempotency key")?;
    validate_slug(&state.factory_id, "factory release factory id")?;
    validate_digest(
        &state.release_subject_sha256,
        "factory release subject SHA-256",
    )?;
    validate_digest(
        &state.manufacturing_package_sha256,
        "factory release manufacturing package SHA-256",
    )?;
    if !matches!(
        state.status,
        FactoryReleaseAdapterStatus::AdapterAccepted
            | FactoryReleaseAdapterStatus::AdapterRejected
            | FactoryReleaseAdapterStatus::AdapterPending
    ) {
        return Err("factory release adapter state status is invalid".into());
    }
    validate_submission_id(&state.submission_id)?;
    validate_digest(&state.state_sha256, "factory release adapter state SHA-256")?;
    if state.state_sha256 != state_digest(state)? {
        return Err("factory release adapter monotonic state digest is invalid".into());
    }
    Ok(())
}

fn state_digest(state: &FactoryReleaseAdapterMonotonicState) -> Result<String, String> {
    domain_hash(
        STATE_DIGEST_DOMAIN,
        &StateDigestMaterial {
            schema_version: state.schema_version,
            state_scope: &state.state_scope,
            sequence: state.sequence,
            previous_state_sha256: &state.previous_state_sha256,
            idempotency_key: &state.idempotency_key,
            submission_id: &state.submission_id,
            factory_id: &state.factory_id,
            provider: state.provider,
            release_subject_sha256: &state.release_subject_sha256,
            manufacturing_package_sha256: &state.manufacturing_package_sha256,
            status: state.status,
        },
    )
}

fn validate_acknowledgement_body(
    body: &[u8],
    intent: &SignedFactoryReleaseSubmissionIntent,
    operation: FactoryReleaseAdapterOperation,
    reconciliation_id: Option<&str>,
    state: &FactoryReleaseAdapterMonotonicState,
) -> Result<(), String> {
    reject_duplicate_json_keys(body)
        .map_err(|error| format!("invalid factory adapter acknowledgement JSON: {error:#}"))?;
    let acknowledgement: FactoryReleaseAdapterAcknowledgement = serde_json::from_slice(body)
        .map_err(|error| format!("invalid factory adapter acknowledgement JSON: {error}"))?;
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
        || acknowledgement.status != state.status
        || acknowledgement.submission_id != state.submission_id
    {
        return Err("factory adapter acknowledgement does not match its monotonic state".into());
    }
    Ok(())
}

fn validate_monotonic_state_entry(
    entry: &FactoryReleaseAdapterMonotonicStateEntry,
) -> Result<(), String> {
    if entry.schema_version != FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION
        || entry.entry_scope != "durable-authenticated-factory-release-monotonic-state-entry-v1"
    {
        return Err("factory release adapter monotonic state entry identity is invalid".into());
    }
    validate_observation_filename(&entry.observation_filename)?;
    validate_artifact_identity(
        &entry.observation,
        MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES,
        "factory release adapter monotonic observation",
    )?;
    validate_monotonic_state_shape(&entry.state)?;
    validate_digest(
        &entry.binding_sha256,
        "factory release adapter monotonic state entry binding SHA-256",
    )?;
    if entry.binding_sha256 != entry_binding(entry)? {
        return Err("factory release adapter monotonic state entry binding is invalid".into());
    }
    Ok(())
}

fn validate_observation_filename(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || value.starts_with('.')
        || !value.ends_with(".json")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        })
    {
        return Err("factory release adapter monotonic observation filename is invalid".into());
    }
    Ok(())
}

fn request_head_values(state: Option<&FactoryReleaseAdapterMonotonicState>) -> (String, String) {
    state.map_or_else(
        || ("none".into(), "none".into()),
        |state| (state.sequence.to_string(), state.state_sha256.clone()),
    )
}

fn validate_request_head_values(sequence: &str, digest: &str) -> Result<(), String> {
    if sequence == "none" || digest == "none" {
        if sequence == "none" && digest == "none" {
            return Ok(());
        }
        return Err("factory release accepted state head is incomplete".into());
    }
    parse_state_sequence(sequence)?;
    validate_digest(digest, "factory release accepted state SHA-256")
}

fn parse_state_sequence(value: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("factory release adapter state sequence is not canonical".into());
    }
    let sequence = value
        .parse::<u64>()
        .map_err(|_| "factory release adapter state sequence is invalid".to_string())?;
    if sequence > MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE {
        return Err("factory release adapter state sequence exceeds its bound".into());
    }
    Ok(sequence)
}

fn parse_optional_state_digest(value: &str) -> Result<Option<String>, String> {
    if value == "none" {
        return Ok(None);
    }
    validate_digest(value, "factory release adapter previous state SHA-256")?;
    Ok(Some(value.into()))
}

fn validate_authentication_failure(failure: &str) -> Result<(), String> {
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
            | "response_state_headers_invalid"
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
    Ok(())
}

fn validate_continuity_failure(failure: &str) -> Result<(), String> {
    if !matches!(
        failure,
        "acknowledgement_not_authenticated"
            | "state_digest_mismatch"
            | "state_chain_genesis_required"
            | "state_subject_changed"
            | "state_rollback_detected"
            | "state_equivocation_detected"
            | "state_sequence_gap_detected"
            | "state_fork_detected"
            | "terminal_state_mutation_detected"
            | "submission_identity_changed"
    ) {
        return Err("factory adapter response continuity failure code is invalid".into());
    }
    Ok(())
}

fn report_binding(
    report: &FactoryReleaseAdapterMonotonicObservationReport,
) -> Result<String, String> {
    domain_hash(
        REPORT_BINDING_DOMAIN,
        &ReportBinding {
            schema_version: report.schema_version,
            verification_scope: &report.verification_scope,
            status: &report.status,
            response_authenticated: report.response_authenticated,
            response_signature_verified: report.response_signature_verified,
            response_content_digest_verified: report.response_content_digest_verified,
            policy_pack_pin_matched: report.policy_pack_pin_matched,
            signer_policy_matched: report.signer_policy_matched,
            signature_time_active: report.signature_time_active,
            acknowledgement_authenticated: report.acknowledgement_authenticated,
            state_headers_authenticated: report.state_headers_authenticated,
            state_digest_verified: report.state_digest_verified,
            request_head_bound: report.request_head_bound,
            transition_verified: report.transition_verified,
            state_continuity_verified: report.state_continuity_verified,
            accepted: report.accepted,
            raw_response_authenticity_verified: report.raw_response_authenticity_verified,
            requested_head_continuity_verified: report.requested_head_continuity_verified,
            selected_ledger_state_committed: report.selected_ledger_state_committed,
            global_non_equivocation_verified: report.global_non_equivocation_verified,
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
            requested_state: &report.requested_state,
            observed_state: &report.observed_state,
            evaluated_at_unix: report.evaluated_at_unix,
            authentication_failure: &report.authentication_failure,
            continuity_failure: &report.continuity_failure,
            adapter_receipt: &report.adapter_receipt,
        },
    )
}

fn entry_binding(entry: &FactoryReleaseAdapterMonotonicStateEntry) -> Result<String, String> {
    domain_hash(
        ENTRY_BINDING_DOMAIN,
        &EntryBinding {
            schema_version: entry.schema_version,
            entry_scope: &entry.entry_scope,
            state: &entry.state,
            observation_filename: &entry.observation_filename,
            observation: &entry.observation,
        },
    )
}

fn domain_hash(domain: &[u8], value: &impl Serialize) -> Result<String, String> {
    let source = serde_json::to_vec(value)
        .map_err(|error| format!("serializing factory adapter monotonic binding: {error}"))?;
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

fn validate_artifact_identity(
    identity: &ExactArtifactIdentity,
    maximum: u64,
    label: &str,
) -> Result<(), String> {
    if identity.bytes == 0 || identity.bytes > maximum {
        return Err(format!("{label} byte count is outside its bound"));
    }
    validate_digest(&identity.sha256, &format!("{label} SHA-256"))
}

fn validate_timestamp(value: u64, label: &str) -> Result<(), String> {
    if value > MAX_SIGNATURE_TIMESTAMP {
        return Err(format!(
            "factory adapter response {label} exceeds its bound"
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
        return Err(format!("{label} must be lowercase SHA-256"));
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_lowercase() && !value.as_bytes()[0].is_ascii_digit()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_submission_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().count() > MAX_SUBMISSION_ID_CHARS
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == 0)
    {
        return Err("factory release adapter submission id is invalid".into());
    }
    Ok(())
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = hex::decode(value).map_err(|error| format!("invalid {label}: {error}"))?;
    decoded
        .try_into()
        .map_err(|_| format!("{label} has the wrong byte length"))
}

fn provider_name(provider: FactoryProvider) -> &'static str {
    match provider {
        FactoryProvider::Jlcpcb => "jlcpcb",
        FactoryProvider::Pcbway => "pcbway",
        FactoryProvider::Generic => "generic",
    }
}

pub(crate) fn factory_release_adapter_monotonic_state_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-adapter-monotonic-state-v1.json",
        "title": "pcbex authenticated monotonic factory release adapter state",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "state_scope", "sequence", "previous_state_sha256",
            "idempotency_key", "submission_id", "factory_id", "provider",
            "release_subject_sha256", "manufacturing_package_sha256", "status",
            "state_sha256"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION},
            "state_scope": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCOPE},
            "sequence": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_ADAPTER_STATE_SEQUENCE},
            "previous_state_sha256": {"oneOf": [{"type": "null"}, digest.clone()]},
            "idempotency_key": digest.clone(),
            "submission_id": {"type": "string", "minLength": 1, "maxLength": MAX_SUBMISSION_ID_CHARS},
            "factory_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
            "release_subject_sha256": digest.clone(),
            "manufacturing_package_sha256": digest.clone(),
            "status": {"enum": ["adapter_accepted", "adapter_rejected", "adapter_pending"]},
            "state_sha256": digest
        }
    })
}

pub(crate) fn factory_release_adapter_monotonic_http_message_signature_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-adapter-monotonic-http-message-signature-v1.json",
        "title": "pcbex RFC 9421 monotonic factory response signature",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "profile", "label", "algorithm", "key_id", "created_at_unix",
            "expires_at_unix", "content_digest", "state_sequence",
            "state_previous_sha256", "state_sha256", "accepted_state_sequence",
            "accepted_state_sha256", "signature_input", "signature"
        ],
        "properties": {
            "profile": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE},
            "label": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL},
            "algorithm": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM},
            "key_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"},
            "created_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_SIGNATURE_TIMESTAMP},
            "expires_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_SIGNATURE_TIMESTAMP},
            "content_digest": {"type": "string", "pattern": "^sha-256=:[A-Za-z0-9+/]{43}=:$", "maxLength": 60},
            "state_sequence": {"type": "string", "pattern": "^(0|[1-9][0-9]{0,3})$", "maxLength": 4},
            "state_previous_sha256": {"type": "string", "pattern": "^(none|[0-9a-f]{64})$", "maxLength": 64},
            "state_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "accepted_state_sequence": {"type": "string", "pattern": "^(none|0|[1-9][0-9]{0,3})$", "maxLength": 4},
            "accepted_state_sha256": {"type": "string", "pattern": "^(none|[0-9a-f]{64})$", "maxLength": 64},
            "signature_input": {"type": "string", "minLength": 1, "maxLength": 8192},
            "signature": {"type": "string", "pattern": "^pcbex-state=:[A-Za-z0-9+/]{86}==:$", "maxLength": 108}
        }
    })
}

pub(crate) fn factory_release_adapter_monotonic_state_entry_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-adapter-monotonic-state-entry-v1.json",
        "title": "pcbex durable authenticated monotonic factory state entry",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "entry_scope", "state", "observation_filename", "observation", "binding_sha256"],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION},
            "entry_scope": {"const": "durable-authenticated-factory-release-monotonic-state-entry-v1"},
            "state": factory_release_adapter_monotonic_state_json_schema(),
            "observation_filename": {"type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,255}\\.json$", "maxLength": 256},
            "observation": {
                "type": "object", "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_BYTES},
                    "sha256": digest.clone()
                }
            },
            "binding_sha256": digest
        }
    })
}

pub(crate) fn factory_release_adapter_monotonic_observation_report_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let false_value = json!({"const": false});
    let v1 = crate::factory_release_adapter_response_authentication::factory_release_adapter_response_authentication_report_json_schema();
    let policy = v1["properties"]["policy_pack"].clone();
    let signer = v1["properties"]["signer"].clone();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-release-adapter-monotonic-observation-report-v1.json",
        "title": "pcbex authenticated monotonic factory release adapter observation",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "verification_scope", "status", "response_authenticated",
            "response_signature_verified", "response_content_digest_verified",
            "policy_pack_pin_matched", "signer_policy_matched", "signature_time_active",
            "acknowledgement_authenticated", "state_headers_authenticated",
            "state_digest_verified", "request_head_bound", "transition_verified",
            "state_continuity_verified", "accepted", "raw_response_authenticity_verified",
            "requested_head_continuity_verified", "selected_ledger_state_committed",
            "global_non_equivocation_verified",
            "endpoint_transport_authenticity_verified", "factory_legal_identity_verified",
            "trusted_time_verified", "server_side_idempotency_enforced", "capacity_reserved",
            "order_placed", "payment_performed", "exactly_once_execution_verified",
            "intent_sha256", "adapter_receipt_sha256", "policy_pack", "signer",
            "response_signature", "requested_state", "observed_state", "evaluated_at_unix",
            "authentication_failure", "continuity_failure", "adapter_receipt", "binding_sha256"
        ],
        "properties": {
            "schema_version": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_STATE_SCHEMA_VERSION},
            "verification_scope": {"const": FACTORY_RELEASE_ADAPTER_MONOTONIC_REPORT_SCOPE},
            "status": {"enum": ["state_continuity_verified", "state_continuity_not_verified"]},
            "response_authenticated": {"type": "boolean"},
            "response_signature_verified": {"type": "boolean"},
            "response_content_digest_verified": {"type": "boolean"},
            "policy_pack_pin_matched": {"const": true},
            "signer_policy_matched": {"type": "boolean"},
            "signature_time_active": {"type": "boolean"},
            "acknowledgement_authenticated": {"type": "boolean"},
            "state_headers_authenticated": {"type": "boolean"},
            "state_digest_verified": {"type": "boolean"},
            "request_head_bound": {"type": "boolean"},
            "transition_verified": {"type": "boolean"},
            "state_continuity_verified": {"type": "boolean"},
            "accepted": {"type": "boolean"},
            "raw_response_authenticity_verified": {"type": "boolean"},
            "requested_head_continuity_verified": {"type": "boolean"},
            "selected_ledger_state_committed": false_value.clone(),
            "global_non_equivocation_verified": false_value.clone(),
            "endpoint_transport_authenticity_verified": false_value.clone(),
            "factory_legal_identity_verified": false_value.clone(),
            "trusted_time_verified": false_value.clone(),
            "server_side_idempotency_enforced": false_value.clone(),
            "capacity_reserved": false_value.clone(),
            "order_placed": false_value.clone(),
            "payment_performed": false_value.clone(),
            "exactly_once_execution_verified": false_value,
            "intent_sha256": digest.clone(),
            "adapter_receipt_sha256": digest.clone(),
            "policy_pack": policy,
            "signer": signer,
            "response_signature": {"oneOf": [{"type": "null"}, factory_release_adapter_monotonic_http_message_signature_json_schema()]},
            "requested_state": {"oneOf": [{"type": "null"}, factory_release_adapter_monotonic_state_json_schema()]},
            "observed_state": {"oneOf": [{"type": "null"}, factory_release_adapter_monotonic_state_json_schema()]},
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_SIGNATURE_TIMESTAMP},
            "authentication_failure": {"oneOf": [
                {"type": "null"},
                {"enum": [
                    "transport_error", "response_signature_headers_missing",
                    "response_signature_headers_duplicated", "response_signature_headers_invalid",
                    "credential_reflection_detected", "response_body_identity_unavailable",
                    "response_content_type_not_profiled", "response_content_digest_invalid",
                    "response_content_digest_mismatch", "response_state_headers_invalid",
                    "response_signature_input_invalid", "response_signature_value_invalid",
                    "response_signer_not_trusted", "response_signer_binding_mismatch",
                    "response_signature_context_invalid", "response_signature_invalid",
                    "response_signature_time_inactive"
                ]}
            ]},
            "continuity_failure": {"oneOf": [
                {"type": "null"},
                {"enum": [
                    "acknowledgement_not_authenticated", "state_digest_mismatch",
                    "state_chain_genesis_required", "state_subject_changed",
                    "state_rollback_detected", "state_equivocation_detected",
                    "state_sequence_gap_detected", "state_fork_detected",
                    "terminal_state_mutation_detected", "submission_identity_changed"
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
    use crate::signed_factory_receipt_release_submission::test_signed_factory_release_submission_intent;
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread::{self, JoinHandle},
    };

    const TOKEN: &str = "test-monotonic-factory-token-1484";
    const KEY_ID: &str = "factory-monotonic-key-a";
    const SECRET_KEY: [u8; 32] = [41; 32];

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
            submission_id: "submission-1484".into(),
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
        body: Vec<u8>,
        headers: Vec<(String, String)>,
    ) -> JoinHandle<Vec<u8>> {
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
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

    fn header_lines(
        signature: &FactoryReleaseAdapterMonotonicHttpMessageSignature,
    ) -> Vec<(String, String)> {
        vec![
            ("Content-Digest".into(), signature.content_digest.clone()),
            (
                "X-PCBEX-State-Sequence".into(),
                signature.state_sequence.clone(),
            ),
            (
                "X-PCBEX-State-Previous-SHA256".into(),
                signature.state_previous_sha256.clone(),
            ),
            (
                "X-PCBEX-State-SHA256".into(),
                signature.state_sha256.clone(),
            ),
            ("Signature-Input".into(), signature.signature_input.clone()),
            ("Signature".into(), signature.signature.clone()),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    fn sign_unchecked_transition(
        intent: &SignedFactoryReleaseSubmissionIntent,
        reconciliation_id: &str,
        endpoint: &str,
        body: &[u8],
        requested_state: Option<&FactoryReleaseAdapterMonotonicState>,
        state_sequence: &str,
        state_previous_sha256: &str,
        state_sha256: &str,
        created_at_unix: u64,
        expires_at_unix: u64,
    ) -> FactoryReleaseAdapterMonotonicHttpMessageSignature {
        let content_digest = content_digest(body);
        let signature_input = signature_input(
            FactoryReleaseAdapterOperation::Reconcile,
            created_at_unix,
            expires_at_unix,
            KEY_ID,
        );
        let base = signature_base(
            intent,
            FactoryReleaseAdapterOperation::Reconcile,
            Some(reconciliation_id),
            endpoint,
            200,
            &content_digest,
            StateHeaderValues {
                sequence: state_sequence,
                previous_sha256: state_previous_sha256,
                state_sha256,
            },
            requested_state,
            &signature_input,
        )
        .unwrap();
        let signature = SigningKey::from_bytes(&SECRET_KEY)
            .sign(base.as_bytes())
            .to_bytes();
        let accepted = request_head_values(requested_state);
        FactoryReleaseAdapterMonotonicHttpMessageSignature {
            profile: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_PROFILE.into(),
            label: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL.into(),
            algorithm: FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_ALGORITHM.into(),
            key_id: KEY_ID.into(),
            created_at_unix,
            expires_at_unix,
            content_digest,
            state_sequence: state_sequence.into(),
            state_previous_sha256: state_previous_sha256.into(),
            state_sha256: state_sha256.into(),
            accepted_state_sequence: accepted.0,
            accepted_state_sha256: accepted.1,
            signature_input,
            signature: format!(
                "{}=:{}:",
                FACTORY_RELEASE_ADAPTER_MONOTONIC_SIGNATURE_LABEL,
                STANDARD.encode(signature)
            ),
        }
    }

    #[test]
    fn monotonic_profile_has_stable_golden_state_and_signature() {
        let (policy, _, _) = policy();
        let endpoint = "http://127.0.0.1:14840/release";
        let package = b"manufacturing-package-1484";
        let intent = test_signed_factory_release_submission_intent(endpoint, package);
        let body = acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
        );
        let state = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let signature = sign_factory_release_adapter_monotonic_http_response(
            &intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            endpoint,
            200,
            &body,
            None,
            &state,
            &policy,
            KEY_ID,
            &SECRET_KEY,
            1_700_000_000,
            1_700_000_120,
        )
        .unwrap();
        assert_eq!(
            state.state_sha256,
            "9ebc8d7a8f9128a21b1f37de2860ec06869670d506235d48e1624cb79c6e0818"
        );
        assert_eq!(
            signature.content_digest,
            "sha-256=:2jtw1GmQ64L2Fe/XixCuCTmdCZYOZTjCglW7jzqYhPM=:"
        );
        assert_eq!(
            signature.signature,
            "pcbex-state=:WC7za7lDZG8SNz6jcBlfA/lncJyqPTcPKD8E69nePET86kqFadq9EMzCVuBWKKUl7kwgShdw3FN+42UdbAZIDA==:"
        );
    }

    #[test]
    fn transition_profile_rejects_rollback_equivocation_gap_fork_and_terminal_mutation() {
        let intent = test_signed_factory_release_submission_intent(
            "http://127.0.0.1:14841/release",
            b"manufacturing-package-1484",
        );
        let genesis = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let next = build_factory_release_adapter_monotonic_state(
            &intent,
            1,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        assert_eq!(
            validate_factory_release_adapter_state_transition(Some(&next), &genesis),
            Err("state_rollback_detected")
        );
        let mut equivocation = genesis.clone();
        equivocation.state_sha256 = "ab".repeat(32);
        assert_eq!(
            validate_factory_release_adapter_state_transition(Some(&genesis), &equivocation),
            Err("state_equivocation_detected")
        );
        let gap = build_factory_release_adapter_monotonic_state(
            &intent,
            2,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        assert_eq!(
            validate_factory_release_adapter_state_transition(Some(&genesis), &gap),
            Err("state_sequence_gap_detected")
        );
        let fork = build_factory_release_adapter_monotonic_state(
            &intent,
            1,
            Some(&"cd".repeat(32)),
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        assert_eq!(
            validate_factory_release_adapter_state_transition(Some(&genesis), &fork),
            Err("state_fork_detected")
        );
        let terminal = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1484",
        )
        .unwrap();
        let terminal_successor = build_factory_release_adapter_monotonic_state(
            &intent,
            1,
            Some(&terminal.state_sha256),
            FactoryReleaseAdapterStatus::AdapterRejected,
            "submission-1484",
        )
        .unwrap();
        assert_eq!(
            validate_factory_release_adapter_state_transition(Some(&terminal), &terminal_successor,),
            Err("terminal_state_mutation_detected")
        );
        let changed_submission = build_factory_release_adapter_monotonic_state(
            &intent,
            1,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "other-submission",
        )
        .unwrap();
        assert_eq!(
            validate_factory_release_adapter_state_transition(Some(&genesis), &changed_submission,),
            Err("submission_identity_changed")
        );
        assert!(
            validate_factory_release_adapter_state_transition(Some(&genesis), &genesis).is_ok()
        );
        assert!(validate_factory_release_adapter_state_transition(Some(&genesis), &next).is_ok());
    }

    #[test]
    fn authenticated_invalid_transitions_remain_authentic_but_never_advance_continuity() {
        let package = b"manufacturing-package-1484";
        let template_intent = test_signed_factory_release_submission_intent(
            "http://127.0.0.1:14842/release",
            package,
        );
        let genesis = build_factory_release_adapter_monotonic_state(
            &template_intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let pending_one = build_factory_release_adapter_monotonic_state(
            &template_intent,
            1,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let equal_other = build_factory_release_adapter_monotonic_state(
            &template_intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1484",
        )
        .unwrap();
        let gap = build_factory_release_adapter_monotonic_state(
            &template_intent,
            2,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1484",
        )
        .unwrap();
        let fork = build_factory_release_adapter_monotonic_state(
            &template_intent,
            1,
            Some(&"ef".repeat(32)),
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1484",
        )
        .unwrap();
        let terminal = equal_other.clone();
        let terminal_mutation = build_factory_release_adapter_monotonic_state(
            &template_intent,
            1,
            Some(&terminal.state_sha256),
            FactoryReleaseAdapterStatus::AdapterRejected,
            "submission-1484",
        )
        .unwrap();
        let cases = [
            (&pending_one, &genesis, "state_rollback_detected"),
            (&genesis, &equal_other, "state_equivocation_detected"),
            (&genesis, &gap, "state_sequence_gap_detected"),
            (&genesis, &fork, "state_fork_detected"),
            (
                &terminal,
                &terminal_mutation,
                "terminal_state_mutation_detected",
            ),
        ];
        let (policy, policy_source, policy_sha256) = policy();
        let (policy_evidence, _) =
            capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                .unwrap();
        let now = crate::current_unix_seconds().unwrap();
        for (index, (requested_template, observed_template, expected_failure)) in
            cases.into_iter().enumerate()
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
            let mut intent = template_intent.clone();
            // Reconciliation endpoints are independent of the submission endpoint, so the
            // state subject remains exactly the same across these local servers.
            intent.submission_endpoint = template_intent.submission_endpoint.clone();
            let intent_source = render_signed_factory_release_submission_intent(&intent).unwrap();
            let intent_sha256 = sha256(&intent_source);
            let reconciliation_id = format!("{index:064x}");
            let body = acknowledgement(
                &intent,
                FactoryReleaseAdapterOperation::Reconcile,
                Some(&reconciliation_id),
                observed_template.status,
            );
            let signature = sign_unchecked_transition(
                &intent,
                &reconciliation_id,
                &endpoint,
                &body,
                Some(requested_template),
                &observed_template.sequence.to_string(),
                observed_template
                    .previous_state_sha256
                    .as_deref()
                    .unwrap_or("none"),
                &observed_template.state_sha256,
                now,
                now + 120,
            );
            let server = serve_once(listener, body, header_lines(&signature));
            let (_, report) = reconcile_monotonic_factory_release_adapter(
                &intent,
                &intent_sha256,
                &endpoint,
                &reconciliation_id,
                Some(requested_template),
                TOKEN,
                5,
                true,
                now,
                &policy_evidence,
                &policy,
            )
            .unwrap();
            server.join().unwrap();
            assert!(report.response_authenticated, "case {expected_failure}");
            assert!(!report.state_continuity_verified, "case {expected_failure}");
            assert!(!report.accepted, "case {expected_failure}");
            assert_eq!(report.continuity_failure.as_deref(), Some(expected_failure),);
            let rendered = render_factory_release_adapter_monotonic_observation_report(
                &report,
                &intent,
                &policy_source,
                &policy_sha256,
            )
            .unwrap();
            parse_factory_release_adapter_monotonic_observation_report(
                &rendered,
                &intent,
                &policy_source,
                &policy_sha256,
            )
            .unwrap();
        }
    }

    #[test]
    fn request_head_body_state_header_and_signature_substitution_fail_authentication() {
        let package = b"manufacturing-package-1484";
        let intent = test_signed_factory_release_submission_intent(
            "http://127.0.0.1:14843/release",
            package,
        );
        let intent_sha256 =
            sha256(&render_signed_factory_release_submission_intent(&intent).unwrap());
        let genesis = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let successor = build_factory_release_adapter_monotonic_state(
            &intent,
            1,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1484",
        )
        .unwrap();
        let (policy, policy_source, policy_sha256) = policy();
        let (policy_evidence, _) =
            capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                .unwrap();
        let now = crate::current_unix_seconds().unwrap();
        for case in ["body", "state_header", "request_head", "signature"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
            let reconciliation_id = match case {
                "body" => "a4".repeat(32),
                "state_header" => "b4".repeat(32),
                "request_head" => "c4".repeat(32),
                "signature" => "d4".repeat(32),
                _ => unreachable!(),
            };
            let body = acknowledgement(
                &intent,
                FactoryReleaseAdapterOperation::Reconcile,
                Some(&reconciliation_id),
                FactoryReleaseAdapterStatus::AdapterAccepted,
            );
            let mut evidence = if case == "request_head" {
                sign_unchecked_transition(
                    &intent,
                    &reconciliation_id,
                    &endpoint,
                    &body,
                    None,
                    "1",
                    &genesis.state_sha256,
                    &successor.state_sha256,
                    now,
                    now + 120,
                )
            } else {
                sign_factory_release_adapter_monotonic_http_response(
                    &intent,
                    FactoryReleaseAdapterOperation::Reconcile,
                    Some(&reconciliation_id),
                    &endpoint,
                    200,
                    &body,
                    Some(&genesis),
                    &successor,
                    &policy,
                    KEY_ID,
                    &SECRET_KEY,
                    now,
                    now + 120,
                )
                .unwrap()
            };
            let sent_body = if case == "body" {
                let mut changed = body;
                changed.push(b'\n');
                changed
            } else {
                body
            };
            if case == "state_header" {
                evidence.state_sequence = "2".into();
            } else if case == "signature" {
                let offset = evidence.signature.find(":").expect("signature framing") + 1;
                let replacement = if evidence.signature.as_bytes()[offset] == b'A' {
                    "B"
                } else {
                    "A"
                };
                evidence
                    .signature
                    .replace_range(offset..=offset, replacement);
            }
            let server = serve_once(listener, sent_body, header_lines(&evidence));
            let (_, report) = reconcile_monotonic_factory_release_adapter(
                &intent,
                &intent_sha256,
                &endpoint,
                &reconciliation_id,
                Some(&genesis),
                TOKEN,
                5,
                true,
                now,
                &policy_evidence,
                &policy,
            )
            .unwrap();
            server.join().unwrap();
            assert!(!report.response_authenticated, "case {case}");
            assert!(!report.state_continuity_verified, "case {case}");
            assert_eq!(
                report.authentication_failure.as_deref(),
                Some(if case == "body" {
                    "response_content_digest_mismatch"
                } else {
                    "response_signature_invalid"
                }),
                "case {case}",
            );
        }
    }

    #[test]
    fn signed_wrong_semantic_state_digest_is_authentic_but_not_continuous() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/release", listener.local_addr().unwrap());
        let package = b"manufacturing-package-1484";
        let intent = test_signed_factory_release_submission_intent(
            "http://127.0.0.1:14844/release",
            package,
        );
        let intent_sha256 =
            sha256(&render_signed_factory_release_submission_intent(&intent).unwrap());
        let genesis = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let reconciliation_id = "e4".repeat(32);
        let body = acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Reconcile,
            Some(&reconciliation_id),
            FactoryReleaseAdapterStatus::AdapterAccepted,
        );
        let now = crate::current_unix_seconds().unwrap();
        let claimed_digest = "42".repeat(32);
        let evidence = sign_unchecked_transition(
            &intent,
            &reconciliation_id,
            &endpoint,
            &body,
            Some(&genesis),
            "1",
            &genesis.state_sha256,
            &claimed_digest,
            now,
            now + 120,
        );
        let server = serve_once(listener, body, header_lines(&evidence));
        let (policy, policy_source, policy_sha256) = policy();
        let (policy_evidence, _) =
            capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                .unwrap();
        let (_, report) = reconcile_monotonic_factory_release_adapter(
            &intent,
            &intent_sha256,
            &endpoint,
            &reconciliation_id,
            Some(&genesis),
            TOKEN,
            5,
            true,
            now,
            &policy_evidence,
            &policy,
        )
        .unwrap();
        server.join().unwrap();
        assert!(report.response_authenticated);
        assert!(!report.state_digest_verified);
        assert!(!report.state_continuity_verified);
        assert_eq!(
            report.continuity_failure.as_deref(),
            Some("state_digest_mismatch")
        );
        let rendered = render_factory_release_adapter_monotonic_observation_report(
            &report,
            &intent,
            &policy_source,
            &policy_sha256,
        )
        .unwrap();
        parse_factory_release_adapter_monotonic_observation_report(
            &rendered,
            &intent,
            &policy_source,
            &policy_sha256,
        )
        .unwrap();
    }

    #[test]
    fn authenticates_genesis_and_one_bound_successor_over_the_real_http_stack() {
        let submit_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let submit_endpoint = format!("http://{}/release", submit_listener.local_addr().unwrap());
        let package = b"manufacturing-package-1484";
        let intent = test_signed_factory_release_submission_intent(&submit_endpoint, package);
        let intent_source = render_signed_factory_release_submission_intent(&intent).unwrap();
        let intent_sha256 = sha256(&intent_source);
        let (policy, policy_source, policy_sha256) = policy();
        let (policy_evidence, _) =
            capture_factory_release_adapter_response_policy(&policy_source, &policy_sha256)
                .unwrap();
        let now = crate::current_unix_seconds().unwrap();
        let submit_body = acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
        );
        let genesis = build_factory_release_adapter_monotonic_state(
            &intent,
            0,
            None,
            FactoryReleaseAdapterStatus::AdapterPending,
            "submission-1484",
        )
        .unwrap();
        let submit_signature = sign_factory_release_adapter_monotonic_http_response(
            &intent,
            FactoryReleaseAdapterOperation::Submit,
            None,
            &submit_endpoint,
            200,
            &submit_body,
            None,
            &genesis,
            &policy,
            KEY_ID,
            &SECRET_KEY,
            now,
            now + 120,
        )
        .unwrap();
        let submit_server = serve_once(
            submit_listener,
            submit_body,
            header_lines(&submit_signature),
        );
        let (_, submit_report) = submit_monotonic_factory_release_adapter(
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
        let submit_request =
            String::from_utf8_lossy(&submit_server.join().unwrap()).to_ascii_lowercase();
        assert!(submit_request.contains("x-pcbex-accepted-state-sequence: none"));
        assert!(submit_request.contains("x-pcbex-accepted-state-sha256: none"));
        assert!(submit_report.response_authenticated);
        assert!(submit_report.state_continuity_verified);
        assert_eq!(submit_report.observed_state.as_ref(), Some(&genesis));
        assert!(!submit_report.accepted);

        let reconcile_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let reconcile_endpoint = format!(
            "http://{}/release",
            reconcile_listener.local_addr().unwrap()
        );
        let reconciliation_id = "84".repeat(32);
        let reconcile_body = acknowledgement(
            &intent,
            FactoryReleaseAdapterOperation::Reconcile,
            Some(&reconciliation_id),
            FactoryReleaseAdapterStatus::AdapterAccepted,
        );
        let successor = build_factory_release_adapter_monotonic_state(
            &intent,
            1,
            Some(&genesis.state_sha256),
            FactoryReleaseAdapterStatus::AdapterAccepted,
            "submission-1484",
        )
        .unwrap();
        let reconcile_signature = sign_factory_release_adapter_monotonic_http_response(
            &intent,
            FactoryReleaseAdapterOperation::Reconcile,
            Some(&reconciliation_id),
            &reconcile_endpoint,
            200,
            &reconcile_body,
            Some(&genesis),
            &successor,
            &policy,
            KEY_ID,
            &SECRET_KEY,
            now,
            now + 120,
        )
        .unwrap();
        let reconcile_server = serve_once(
            reconcile_listener,
            reconcile_body,
            header_lines(&reconcile_signature),
        );
        let (_, reconcile_report) = reconcile_monotonic_factory_release_adapter(
            &intent,
            &intent_sha256,
            &reconcile_endpoint,
            &reconciliation_id,
            Some(&genesis),
            TOKEN,
            5,
            true,
            now,
            &policy_evidence,
            &policy,
        )
        .unwrap();
        let reconcile_request =
            String::from_utf8_lossy(&reconcile_server.join().unwrap()).to_ascii_lowercase();
        assert!(reconcile_request.contains("x-pcbex-accepted-state-sequence: 0"));
        assert!(reconcile_request.contains(&format!(
            "x-pcbex-accepted-state-sha256: {}",
            genesis.state_sha256
        )));
        assert!(reconcile_report.response_authenticated);
        assert!(reconcile_report.state_continuity_verified);
        assert!(reconcile_report.accepted);
        assert_eq!(reconcile_report.requested_state.as_ref(), Some(&genesis));
        assert_eq!(reconcile_report.observed_state.as_ref(), Some(&successor));
        assert!(!reconcile_report.global_non_equivocation_verified);
        assert!(!reconcile_report.trusted_time_verified);
        assert!(!reconcile_report.capacity_reserved);
        assert!(!reconcile_report.order_placed);
        assert!(!reconcile_report.payment_performed);
        let rendered = render_factory_release_adapter_monotonic_observation_report(
            &reconcile_report,
            &intent,
            &policy_source,
            &policy_sha256,
        )
        .unwrap();
        assert_eq!(
            parse_factory_release_adapter_monotonic_observation_report(
                &rendered,
                &intent,
                &policy_source,
                &policy_sha256,
            )
            .unwrap(),
            reconcile_report
        );
        let observation_name = monotonic_factory_release_reconciliation_filename(
            &intent.idempotency_key,
            &reconciliation_id,
        )
        .unwrap();
        let entry = build_factory_release_adapter_monotonic_state_entry(
            &successor,
            &observation_name,
            &rendered,
        )
        .unwrap();
        let entry_source = render_factory_release_adapter_monotonic_state_entry(&entry).unwrap();
        assert_eq!(
            parse_factory_release_adapter_monotonic_state_entry(&entry_source).unwrap(),
            entry
        );
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
    fn monotonic_schemas_are_recursively_closed_and_keep_nonclaims_false() {
        for schema in [
            factory_release_adapter_monotonic_state_json_schema(),
            factory_release_adapter_monotonic_http_message_signature_json_schema(),
            factory_release_adapter_monotonic_state_entry_json_schema(),
            factory_release_adapter_monotonic_observation_report_json_schema(),
        ] {
            assert_recursively_closed(&schema);
        }
        let report = factory_release_adapter_monotonic_observation_report_json_schema();
        assert_eq!(
            report["properties"]["global_non_equivocation_verified"]["const"],
            false
        );
        assert_eq!(
            report["properties"]["selected_ledger_state_committed"]["const"],
            false
        );
        assert_eq!(
            report["properties"]["trusted_time_verified"]["const"],
            false
        );
        assert_eq!(report["properties"]["capacity_reserved"]["const"], false);
        assert_eq!(report["properties"]["order_placed"]["const"], false);
        assert_eq!(report["properties"]["payment_performed"]["const"], false);
    }
}
