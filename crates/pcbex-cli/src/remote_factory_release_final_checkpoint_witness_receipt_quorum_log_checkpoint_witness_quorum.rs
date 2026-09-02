//! Parallel acquisition of a factory final receipt-quorum checkpoint witness quorum.
//!
//! The v1.527 boundary preserves the v1.521 report, v1.523 checkpoint, v1.524
//! witness/quorum, v1.525 trust-state, and v1.526 receipt wire contracts. It
//! validates every endpoint and trust input,
//! then production-verifies the shared public evidence before any credential
//! lookup or network request. Bounded scoped workers acquire independent
//! unchanged v1.524 witnesses through the v1.526 adapter. Successful responses
//! and credential-free receipts are retained alongside coarse failure classes,
//! and the production v1.524 verifier constructs the final quorum.

use crate::factory_release_state_transparency_external_gossip_registry::MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION;
use crate::remote_factory_release_final_checkpoint_witness::{
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
    remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema,
    remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state_json_schema,
    render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state,
    render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness,
    signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_json_schema,
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report,
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses,
};
use crate::remote_factory_release_final_checkpoint_witness_acquisition::{
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    preflight_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_request,
    remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_json_schema,
    render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt,
    request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness,
    request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_with_trust_state,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt,
    verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_with_trust_state,
};
use crate::remote_factory_release_state_transparency_external_gossip_registry_checkpoint_witness::{
    MAX_TIMESTAMP, decode_hex, digest_schema, parse_canonical,
    parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report,
    parse_remote_receipt_quorum_approval_log,
    parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint,
    render_bounded, sha256, slug_schema, validate_digest, validate_endpoint, validate_env_name,
    validate_nonweak_public_key, validate_slug,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeSet;

const PROTOCOL: &str = "pcbex-remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-acquisition-v1";
const MAX_WITNESSES: usize = 100;
const MAX_PARALLELISM: u32 = 16;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_ENV_NAME_BYTES: usize = 128;
type WitnessKeyBinding = ([u8; 32], Option<String>, Option<u64>);

pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_MANIFEST_BYTES: u64 =
    1024 * 1024;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_ACQUISITION_REPORT_BYTES:
    u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifestMember
{
    pub(crate) endpoint: String,
    pub(crate) witness_id: String,
    pub(crate) witness_public_key: Option<String>,
    pub(crate) witness_trust_state: Option<
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessTrustState,
    >,
    pub(crate) bearer_token_env: Option<String>,
    pub(crate) timeout_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest {
    pub(crate) schema_version: u32,
    pub(crate) minimum_witnesses: u32,
    pub(crate) maximum_parallelism: u32,
    pub(crate) members: Vec<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifestMember>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus
{
    Verified,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode
{
    Credential,
    Transport,
    HttpStatus,
    ContentType,
    ResponseLimit,
    InvalidResponse,
    IdentityMismatch,
    Verification,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember {
    pub(crate) endpoint: String,
    pub(crate) witness_id: String,
    pub(crate) witness_public_key: String,
    pub(crate) witness_key_trust_state_sha256: Option<String>,
    pub(crate) witness_key_generation: Option<u64>,
    pub(crate) status: RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus,
    pub(crate) failure_code:
        Option<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode>,
    pub(crate) witness: Option<
        SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness,
    >,
    pub(crate) receipt: Option<
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt,
    >,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport {
    pub(crate) schema_version: u32,
    pub(crate) protocol: String,
    pub(crate) manifest_sha256: String,
    pub(crate) final_checkpoint_witness_receipt_quorum_report_source_sha256: String,
    pub(crate) final_admission_log_source_sha256: String,
    pub(crate) checkpoint_source_sha256: String,
    pub(crate) checkpoint_public_key: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) minimum_witnesses: u32,
    pub(crate) maximum_parallelism: u32,
    pub(crate) requested_witnesses: u32,
    pub(crate) verified_witnesses: u32,
    pub(crate) failed_witnesses: u32,
    pub(crate) members: Vec<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember>,
    pub(crate) quorum:
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    pub(crate) quorum_met: bool,
}

pub(crate) fn render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(
    manifest: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest,
) -> Result<Vec<u8>, String> {
    validate_manifest(manifest, true)?;
    render_bounded(
        manifest,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_MANIFEST_BYTES,
        "remote factory release final checkpoint witness quorum manifest",
    )
}

pub(crate) fn parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest,
    String,
> {
    let manifest = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_MANIFEST_BYTES,
        "remote factory release final checkpoint witness quorum manifest",
    )?;
    validate_manifest(&manifest, true)?;
    Ok(manifest)
}

pub(crate) fn render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport,
) -> Result<Vec<u8>, String> {
    validate_acquisition_report(report)?;
    render_bounded(
        report,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_ACQUISITION_REPORT_BYTES,
        "remote factory release final checkpoint witness quorum acquisition report",
    )
}

pub(crate) fn parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
    source: &[u8],
) -> Result<RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport, String>{
    let report = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_FINAL_CHECKPOINT_WITNESS_RECEIPT_QUORUM_LOG_CHECKPOINT_WITNESS_QUORUM_ACQUISITION_REPORT_BYTES,
        "remote factory release final checkpoint witness quorum acquisition report",
    )?;
    validate_acquisition_report(&report)?;
    Ok(report)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum(
    manifest_source: &[u8],
    quorum_report_source: &[u8],
    admission_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport,
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    ),
    String,
>{
    let manifest =
        parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(manifest_source)?;
    validate_manifest(&manifest, allow_http_loopback)?;
    validate_manifest_against_checkpoint_key(&manifest, trusted_checkpoint_public_key)?;

    // Establish the one shared public context before any worker can read a
    // credential or initiate a connection.
    preflight_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_request(
        quorum_report_source,
        admission_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        evaluated_at_unix,
    )?;

    let mut members = Vec::with_capacity(manifest.members.len());
    for chunk in manifest
        .members
        .chunks(manifest.maximum_parallelism as usize)
    {
        let batch = std::thread::scope(|scope| {
            let handles = chunk
                .iter()
                .map(|member| {
                    scope.spawn(move || {
                        request_member(
                            member,
                            quorum_report_source,
                            admission_log_source,
                            checkpoint_source,
                            trusted_checkpoint_public_key,
                            evaluated_at_unix,
                            allow_http_loopback,
                        )
                    })
                })
                .collect::<Vec<_>>();
            let mut results = Vec::with_capacity(handles.len());
            for handle in handles {
                results.push(handle.join().map_err(|_| {
                    "remote final checkpoint witness acquisition worker panicked".to_string()
                })??);
            }
            Ok::<_, String>(results)
        })?;
        members.extend(batch);
    }

    let (witnesses, trusted_witness_keys) = verified_witnesses_and_keys(&members)?;
    let semantic_report = parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        quorum_report_source,
    )?;
    let admission_log = parse_remote_receipt_quorum_approval_log(admission_log_source)?;
    let checkpoint =
        parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
            checkpoint_source,
        )?;
    let quorum = verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
        &semantic_report,
        &admission_log,
        &checkpoint,
        trusted_checkpoint_public_key,
        &witnesses,
        &trusted_witness_keys,
        manifest.minimum_witnesses,
        evaluated_at_unix,
    )?;
    let verified_witnesses = u32::try_from(witnesses.len())
        .map_err(|_| "verified final checkpoint witness count overflow".to_string())?;
    let requested_witnesses = u32::try_from(manifest.members.len())
        .map_err(|_| "requested final checkpoint witness count overflow".to_string())?;
    let report = RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport {
        schema_version: 1,
        protocol: PROTOCOL.into(),
        manifest_sha256: sha256(manifest_source),
        final_checkpoint_witness_receipt_quorum_report_source_sha256: sha256(quorum_report_source),
        final_admission_log_source_sha256: sha256(admission_log_source),
        checkpoint_source_sha256: sha256(checkpoint_source),
        checkpoint_public_key: hex::encode(trusted_checkpoint_public_key),
        evaluated_at_unix,
        minimum_witnesses: manifest.minimum_witnesses,
        maximum_parallelism: manifest.maximum_parallelism,
        requested_witnesses,
        verified_witnesses,
        failed_witnesses: requested_witnesses - verified_witnesses,
        members,
        quorum: quorum.clone(),
        quorum_met: quorum.quorum_met,
    };
    validate_acquisition_report(&report)?;
    Ok((report, quorum))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport,
    manifest_source: &[u8],
    quorum_report_source: &[u8],
    admission_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport,
    String,
> {
    validate_acquisition_report(report)?;
    let manifest =
        parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(manifest_source)?;
    validate_manifest_against_checkpoint_key(&manifest, trusted_checkpoint_public_key)?;
    if report.manifest_sha256 != sha256(manifest_source)
        || report.final_checkpoint_witness_receipt_quorum_report_source_sha256
            != sha256(quorum_report_source)
        || report.final_admission_log_source_sha256 != sha256(admission_log_source)
        || report.checkpoint_source_sha256 != sha256(checkpoint_source)
        || report.checkpoint_public_key != hex::encode(trusted_checkpoint_public_key)
        || report.minimum_witnesses != manifest.minimum_witnesses
        || report.maximum_parallelism != manifest.maximum_parallelism
        || report.requested_witnesses != manifest.members.len() as u32
        || report.members.len() != manifest.members.len()
    {
        return Err(
            "remote final checkpoint witness acquisition report is bound to different retained evidence or configuration"
                .into(),
        );
    }

    preflight_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_request(
        quorum_report_source,
        admission_log_source,
        checkpoint_source,
        trusted_checkpoint_public_key,
        report.evaluated_at_unix,
    )?;

    for (configured, observed) in manifest.members.iter().zip(&report.members) {
        let (trusted_key, trust_digest, trust_generation) = member_key_and_binding(configured)?;
        if observed.endpoint != configured.endpoint
            || observed.witness_id != configured.witness_id
            || observed.witness_public_key != hex::encode(trusted_key)
            || observed.witness_key_trust_state_sha256 != trust_digest
            || observed.witness_key_generation != trust_generation
        {
            return Err(
                "remote final checkpoint witness acquisition member is bound to different manifest trust"
                    .into(),
            );
        }
        if observed.status == RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Verified
        {
            let witness = observed
                .witness
                .as_ref()
                .ok_or_else(|| "verified remote final checkpoint witness is absent".to_string())?;
            let receipt = observed.receipt.as_ref().ok_or_else(|| {
                "verified remote final checkpoint witness receipt is absent".to_string()
            })?;
            let response = render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
                witness,
            )?;
            let verified = if let Some(state) = &configured.witness_trust_state {
                let state_source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
                    state,
                )?;
                verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_with_trust_state(
                    receipt,
                    quorum_report_source,
                    admission_log_source,
                    checkpoint_source,
                    trusted_checkpoint_public_key,
                    &response,
                    &configured.witness_id,
                    &state_source,
                )?
            } else {
                verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                    receipt,
                    quorum_report_source,
                    admission_log_source,
                    checkpoint_source,
                    trusted_checkpoint_public_key,
                    &response,
                    &configured.witness_id,
                    &trusted_key,
                )?
            };
            if &verified != witness {
                return Err(
                    "remote final checkpoint witness acquisition replay returned different evidence"
                        .into(),
                );
            }
        }
    }

    let (witnesses, trusted_witness_keys) = verified_witnesses_and_keys(&report.members)?;
    let semantic_report = parse_remote_factory_release_registry_history_receipt_quorum_log_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_quorum_report(
        quorum_report_source,
    )?;
    let admission_log = parse_remote_receipt_quorum_approval_log(admission_log_source)?;
    let checkpoint =
        parse_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint(
            checkpoint_source,
        )?;
    let quorum = verify_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witnesses(
        &semantic_report,
        &admission_log,
        &checkpoint,
        trusted_checkpoint_public_key,
        &witnesses,
        &trusted_witness_keys,
        manifest.minimum_witnesses,
        report.evaluated_at_unix,
    )?;
    if quorum != report.quorum || quorum.quorum_met != report.quorum_met {
        return Err(
            "remote final checkpoint witness acquisition report contains a different final quorum"
                .into(),
        );
    }
    Ok(quorum)
}

#[allow(clippy::too_many_arguments)]
fn request_member(
    member: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifestMember,
    quorum_report_source: &[u8],
    admission_log_source: &[u8],
    checkpoint_source: &[u8],
    trusted_checkpoint_public_key: &[u8; 32],
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember,
    String,
> {
    let (trusted_key, trust_digest, trust_generation) = member_key_and_binding(member)?;
    let result = if let Some(state) = &member.witness_trust_state {
        let state_source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
            state,
        )?;
        request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_with_trust_state(
            quorum_report_source,
            admission_log_source,
            checkpoint_source,
            trusted_checkpoint_public_key,
            &member.endpoint,
            &member.witness_id,
            &state_source,
            member.bearer_token_env.as_deref(),
            member.timeout_seconds,
            evaluated_at_unix,
            allow_http_loopback,
        )
    } else {
        request_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
            quorum_report_source,
            admission_log_source,
            checkpoint_source,
            trusted_checkpoint_public_key,
            &member.endpoint,
            &member.witness_id,
            &trusted_key,
            member.bearer_token_env.as_deref(),
            member.timeout_seconds,
            evaluated_at_unix,
            allow_http_loopback,
        )
    };
    let (status, failure_code, witness, receipt) = match result {
        Ok((witness, receipt)) if witness.witness_id == member.witness_id => (
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Verified,
            None,
            Some(witness),
            Some(receipt),
        ),
        Ok(_) => (
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Failed,
            Some(
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::IdentityMismatch,
            ),
            None,
            None,
        ),
        Err(error) => (
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Failed,
            Some(classify_failure(&error)),
            None,
            None,
        ),
    };
    Ok(
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember {
            endpoint: member.endpoint.clone(),
            witness_id: member.witness_id.clone(),
            witness_public_key: hex::encode(trusted_key),
            witness_key_trust_state_sha256: trust_digest,
            witness_key_generation: trust_generation,
            status,
            failure_code,
            witness,
            receipt,
        },
    )
}

fn classify_failure(
    error: &str,
) -> RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode
{
    if error.contains("bearer-token environment") {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::Credential
    } else if error.contains("unexpected HTTP status") || error.contains("http status:") {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::HttpStatus
    } else if error.contains("HTTPS request failed") {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::Transport
    } else if error.contains("Content-Type") {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::ContentType
    } else if error.contains("response exceeds") || error.contains("reading bounded") {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::ResponseLimit
    } else if error.contains("identity does not match") {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::IdentityMismatch
    } else if error.contains("invalid signed factory")
        || error.contains("not canonical pretty JSON")
        || error.contains("duplicate")
    {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::InvalidResponse
    } else {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::Verification
    }
}

fn member_key_and_binding(
    member: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifestMember,
) -> Result<WitnessKeyBinding, String> {
    match (&member.witness_public_key, &member.witness_trust_state) {
        (Some(public_key), None) => {
            let key = decode_hex::<32>(public_key, "remote final checkpoint witness public key")?;
            validate_nonweak_public_key(&key, "remote final checkpoint witness public key")?;
            Ok((key, None, None))
        }
        (None, Some(state)) => {
            validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
                state,
            )?;
            if state.witness_id != member.witness_id {
                return Err(
                    "remote final checkpoint witness identity does not match its trust state"
                        .into(),
                );
            }
            let key = decode_hex::<32>(
                &state.current_public_key,
                "remote final checkpoint witness trust-state public key",
            )?;
            let source = render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state(
                state,
            )?;
            Ok((key, Some(sha256(&source)), Some(state.generation)))
        }
        _ => Err(
            "remote final checkpoint witness must select exactly one direct key or trust state"
                .into(),
        ),
    }
}

fn validate_manifest(
    manifest: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest,
    allow_http_loopback: bool,
) -> Result<(), String> {
    if manifest.schema_version != 1
        || !(2..=MAX_WITNESSES).contains(&manifest.members.len())
        || !(2..=manifest.members.len() as u32).contains(&manifest.minimum_witnesses)
        || !(2..=MAX_PARALLELISM).contains(&manifest.maximum_parallelism)
        || manifest.maximum_parallelism > manifest.members.len() as u32
    {
        return Err("remote final checkpoint witness quorum manifest bounds are invalid".into());
    }
    let mut witness_ids = BTreeSet::new();
    let mut witness_keys = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut previous_witness_id: Option<&str> = None;
    for member in &manifest.members {
        if member.endpoint.len() > MAX_ENDPOINT_BYTES {
            return Err("remote final checkpoint witness endpoint exceeds its bound".into());
        }
        validate_endpoint(&member.endpoint, allow_http_loopback)?;
        validate_slug(&member.witness_id, "remote final checkpoint witness id")?;
        if !(1..=600).contains(&member.timeout_seconds) {
            return Err(
                "remote final checkpoint witness timeout must be between 1 and 600 seconds".into(),
            );
        }
        if let Some(variable) = &member.bearer_token_env {
            if variable.len() > MAX_ENV_NAME_BYTES {
                return Err("bearer-token environment name exceeds its bound".into());
            }
            validate_env_name(variable)?;
        }
        let (key, _, _) = member_key_and_binding(member)?;
        if previous_witness_id.is_some_and(|previous| previous >= member.witness_id.as_str()) {
            return Err(
                "remote final checkpoint witness quorum manifest members must be sorted by distinct witness id"
                    .into(),
            );
        }
        previous_witness_id = Some(&member.witness_id);
        if !witness_ids.insert(member.witness_id.as_str())
            || !witness_keys.insert(key)
            || !endpoints.insert(member.endpoint.as_str())
        {
            return Err(
                "remote final checkpoint witness quorum manifest repeats an identity, key, or endpoint"
                    .into(),
            );
        }
    }
    Ok(())
}

fn validate_manifest_against_checkpoint_key(
    manifest: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest,
    trusted_checkpoint_public_key: &[u8; 32],
) -> Result<(), String> {
    validate_nonweak_public_key(
        trusted_checkpoint_public_key,
        "trusted final checkpoint public key",
    )?;
    for member in &manifest.members {
        if member_key_and_binding(member)?.0 == *trusted_checkpoint_public_key {
            return Err(
                "remote final checkpoint witness key must be independent from the checkpoint signing key"
                    .into(),
            );
        }
    }
    Ok(())
}

fn verified_witnesses_and_keys(
    members: &[RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember],
) -> Result<
    (
        Vec<SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness>,
        Vec<[u8; 32]>,
    ),
    String,
> {
    let mut witnesses = Vec::new();
    let mut keys = Vec::new();
    for member in members {
        if member.status == RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Verified {
            witnesses.push(
                member.witness.clone().ok_or_else(|| {
                    "verified remote final checkpoint witness is absent".to_string()
                })?,
            );
            keys.push(decode_hex::<32>(
                &member.witness_public_key,
                "remote final checkpoint witness public key",
            )?);
        }
    }
    Ok((witnesses, keys))
}

fn validate_acquisition_report(
    report: &RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport,
) -> Result<(), String> {
    if report.schema_version != 1
        || report.protocol != PROTOCOL
        || report.evaluated_at_unix > MAX_TIMESTAMP
        || !(2..=MAX_WITNESSES as u32).contains(&report.requested_witnesses)
        || !(2..=report.requested_witnesses).contains(&report.minimum_witnesses)
        || !(2..=MAX_PARALLELISM).contains(&report.maximum_parallelism)
        || report.maximum_parallelism > report.requested_witnesses
        || report.members.len() != report.requested_witnesses as usize
        || report.verified_witnesses > report.requested_witnesses
        || report.failed_witnesses > report.requested_witnesses
        || report
            .verified_witnesses
            .checked_add(report.failed_witnesses)
            != Some(report.requested_witnesses)
        || report.quorum_met != report.quorum.quorum_met
    {
        return Err(
            "remote final checkpoint witness quorum acquisition report invariants are invalid"
                .into(),
        );
    }
    for (digest, label) in [
        (&report.manifest_sha256, "witness quorum manifest SHA-256"),
        (
            &report.final_checkpoint_witness_receipt_quorum_report_source_sha256,
            "checkpoint-witness receipt quorum report source SHA-256",
        ),
        (
            &report.final_admission_log_source_sha256,
            "admission log source SHA-256",
        ),
        (
            &report.checkpoint_source_sha256,
            "checkpoint source SHA-256",
        ),
    ] {
        validate_digest(digest, label)?;
    }
    let checkpoint_key = decode_hex::<32>(
        &report.checkpoint_public_key,
        "remote final checkpoint public key",
    )?;
    validate_nonweak_public_key(&checkpoint_key, "remote final checkpoint public key")?;
    validate_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report(
        &report.quorum,
    )?;
    if report.quorum.minimum_witnesses != report.minimum_witnesses
        || report.quorum.evaluated_at_unix != report.evaluated_at_unix
        || report.quorum.valid_witnesses != report.verified_witnesses
    {
        return Err(
            "remote final checkpoint witness acquisition report quorum summary is inconsistent"
                .into(),
        );
    }

    let mut witness_ids = BTreeSet::new();
    let mut witness_keys = BTreeSet::new();
    let mut endpoints = BTreeSet::new();
    let mut verified_ids = BTreeSet::new();
    let mut verified_keys = BTreeSet::new();
    let mut request_digests = BTreeSet::new();
    let mut verified_count = 0_u32;
    let mut failed_count = 0_u32;
    let mut previous_witness_id: Option<&str> = None;
    for member in &report.members {
        if member.endpoint.len() > MAX_ENDPOINT_BYTES {
            return Err("remote final checkpoint witness endpoint exceeds its bound".into());
        }
        validate_endpoint(&member.endpoint, true)?;
        validate_slug(&member.witness_id, "remote final checkpoint witness id")?;
        let key = decode_hex::<32>(
            &member.witness_public_key,
            "remote final checkpoint witness public key",
        )?;
        validate_nonweak_public_key(&key, "remote final checkpoint witness public key")?;
        if key == checkpoint_key {
            return Err(
                "remote final checkpoint witness key reuses the checkpoint signing role".into(),
            );
        }
        match (
            &member.witness_key_trust_state_sha256,
            member.witness_key_generation,
        ) {
            (None, None) => {}
            (Some(digest), Some(generation)) => {
                validate_digest(
                    digest,
                    "remote final checkpoint witness trust-state SHA-256",
                )?;
                if generation
                    > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
                {
                    return Err(
                        "remote final checkpoint witness trust-state generation exceeds its bound"
                            .into(),
                    );
                }
            }
            _ => {
                return Err(
                    "remote final checkpoint witness trust-state binding is incomplete".into(),
                );
            }
        }
        if previous_witness_id.is_some_and(|previous| previous >= member.witness_id.as_str()) {
            return Err(
                "remote final checkpoint witness acquisition members must be sorted by distinct witness id"
                    .into(),
            );
        }
        previous_witness_id = Some(&member.witness_id);
        if !witness_ids.insert(member.witness_id.as_str())
            || !witness_keys.insert(key)
            || !endpoints.insert(member.endpoint.as_str())
        {
            return Err(
                "remote final checkpoint witness acquisition repeats an identity, key, or endpoint"
                    .into(),
            );
        }
        match member.status {
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Verified => {
                verified_count += 1;
                if member.failure_code.is_some() {
                    return Err(
                        "verified remote final checkpoint witness carries a failure code".into(),
                    );
                }
                let witness = member.witness.as_ref().ok_or_else(|| {
                    "verified remote final checkpoint witness is absent".to_string()
                })?;
                let receipt = member.receipt.as_ref().ok_or_else(|| {
                    "verified remote final checkpoint witness receipt is absent".to_string()
                })?;
                let response = render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
                    witness,
                )?;
                render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt(
                    receipt,
                )?;
                let compact_witness = serde_json::to_vec(witness).map_err(|error| {
                    format!("serializing embedded remote final checkpoint witness: {error}")
                })?;
                if witness.witness_id != member.witness_id
                    || witness.public_key != member.witness_public_key
                    || receipt.endpoint != member.endpoint
                    || receipt.witness_id != member.witness_id
                    || receipt.witness_public_key != member.witness_public_key
                    || receipt.witness_key_trust_state_sha256
                        != member.witness_key_trust_state_sha256
                    || receipt.witness_key_generation != member.witness_key_generation
                    || receipt.evaluated_at_unix != report.evaluated_at_unix
                    || receipt.final_checkpoint_witness_receipt_quorum_report_source_sha256
                        != report.final_checkpoint_witness_receipt_quorum_report_source_sha256
                    || receipt.final_admission_log_source_sha256 != report.final_admission_log_source_sha256
                    || receipt.checkpoint_source_sha256 != report.checkpoint_source_sha256
                    || receipt.checkpoint_public_key != report.checkpoint_public_key
                    || receipt.response_bytes != response.len() as u64
                    || receipt.response_sha256 != sha256(&response)
                    || receipt.witness_sha256 != sha256(&compact_witness)
                {
                    return Err(
                        "verified remote final checkpoint witness acquisition binding is inconsistent"
                            .into(),
                    );
                }
                request_digests.insert(receipt.request_sha256.as_str());
                verified_ids.insert(member.witness_id.clone());
                verified_keys.insert(member.witness_public_key.clone());
            }
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Failed => {
                failed_count += 1;
                if member.failure_code.is_none()
                    || member.witness.is_some()
                    || member.receipt.is_some()
                {
                    return Err(
                        "failed remote final checkpoint witness acquisition retains invalid success evidence"
                            .into(),
                    );
                }
            }
        }
    }
    if verified_count != report.verified_witnesses
        || failed_count != report.failed_witnesses
        || request_digests.len() != verified_count as usize
        || report.quorum.witness_ids != verified_ids.into_iter().collect::<Vec<_>>()
        || report.quorum.witness_public_keys != verified_keys.into_iter().collect::<Vec<_>>()
    {
        return Err(
            "remote final checkpoint witness acquisition member summary is inconsistent".into(),
        );
    }
    Ok(())
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest_json_schema()
-> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-manifest-v1.json",
        "title": "pcbex remote factory final receipt-quorum checkpoint witness quorum manifest",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "minimum_witnesses", "maximum_parallelism", "members"],
        "properties": {
            "schema_version": {"const": 1},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": MAX_WITNESSES},
            "maximum_parallelism": {"type": "integer", "minimum": 2, "maximum": MAX_PARALLELISM},
            "members": {
                "type": "array", "minItems": 2, "maxItems": MAX_WITNESSES,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "endpoint", "witness_id", "witness_public_key", "witness_trust_state",
                        "bearer_token_env", "timeout_seconds"
                    ],
                    "properties": {
                        "endpoint": endpoint_schema(),
                        "witness_id": slug_schema(),
                        "witness_public_key": {"oneOf": [{"type": "null"}, digest_schema()]},
                        "witness_trust_state": {
                            "oneOf": [
                                {"type": "null"},
                                remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state_json_schema()
                            ]
                        },
                        "bearer_token_env": {
                            "oneOf": [
                                {"type": "null"},
                                {"type": "string", "minLength": 1, "maxLength": MAX_ENV_NAME_BYTES, "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"}
                            ]
                        },
                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600}
                    },
                    "oneOf": [
                        {
                            "properties": {
                                "witness_public_key": digest_schema(),
                                "witness_trust_state": {"type": "null"}
                            }
                        },
                        {
                            "properties": {
                                "witness_public_key": {"type": "null"},
                                "witness_trust_state": remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_trust_state_json_schema()
                            }
                        }
                    ]
                }
            }
        }
    })
}

pub(crate) fn remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report_json_schema()
-> Value {
    let nullable_digest = json!({"oneOf": [{"type": "null"}, digest_schema()]});
    let nullable_generation = json!({
        "oneOf": [
            {"type": "null"},
            {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            }
        ]
    });
    let failure_codes = json!({
        "oneOf": [
            {"type": "null"},
            {"enum": [
                "credential", "transport", "http_status", "content_type", "response_limit",
                "invalid_response", "identity_mismatch", "verification"
            ]}
        ]
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-quorum-acquisition-report-v1.json",
        "title": "pcbex remote factory final receipt-quorum checkpoint witness quorum acquisition report",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "protocol", "manifest_sha256",
            "final_checkpoint_witness_receipt_quorum_report_source_sha256",
            "final_admission_log_source_sha256", "checkpoint_source_sha256",
            "checkpoint_public_key", "evaluated_at_unix", "minimum_witnesses",
            "maximum_parallelism", "requested_witnesses", "verified_witnesses",
            "failed_witnesses", "members", "quorum", "quorum_met"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "protocol": {"const": PROTOCOL},
            "manifest_sha256": digest_schema(),
            "final_checkpoint_witness_receipt_quorum_report_source_sha256": digest_schema(),
            "final_admission_log_source_sha256": digest_schema(),
            "checkpoint_source_sha256": digest_schema(),
            "checkpoint_public_key": digest_schema(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "minimum_witnesses": {"type": "integer", "minimum": 2, "maximum": MAX_WITNESSES},
            "maximum_parallelism": {"type": "integer", "minimum": 2, "maximum": MAX_PARALLELISM},
            "requested_witnesses": {"type": "integer", "minimum": 2, "maximum": MAX_WITNESSES},
            "verified_witnesses": {"type": "integer", "minimum": 0, "maximum": MAX_WITNESSES},
            "failed_witnesses": {"type": "integer", "minimum": 0, "maximum": MAX_WITNESSES},
            "members": {
                "type": "array", "minItems": 2, "maxItems": MAX_WITNESSES,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "endpoint", "witness_id", "witness_public_key",
                        "witness_key_trust_state_sha256", "witness_key_generation",
                        "status", "failure_code", "witness", "receipt"
                    ],
                    "properties": {
                        "endpoint": endpoint_schema(),
                        "witness_id": slug_schema(),
                        "witness_public_key": digest_schema(),
                        "witness_key_trust_state_sha256": nullable_digest,
                        "witness_key_generation": nullable_generation,
                        "status": {"enum": ["verified", "failed"]},
                        "failure_code": failure_codes,
                        "witness": {
                            "oneOf": [
                                {"type": "null"},
                                signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_json_schema()
                            ]
                        },
                        "receipt": {
                            "oneOf": [
                                {"type": "null"},
                                remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_receipt_json_schema()
                            ]
                        }
                    }
                }
            },
            "quorum": remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_report_json_schema(),
            "quorum_met": {"type": "boolean"}
        }
    })
}

fn endpoint_schema() -> Value {
    json!({
        "oneOf": [
            {"type": "string", "minLength": 1, "maxLength": MAX_ENDPOINT_BYTES, "pattern": "^https://"},
            {"type": "string", "minLength": 1, "maxLength": MAX_ENDPOINT_BYTES, "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(byte: u8) -> String {
        hex::encode(
            SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .to_bytes(),
        )
    }

    fn manifest()
    -> RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest
    {
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifest {
            schema_version: 1,
            minimum_witnesses: 2,
            maximum_parallelism: 2,
            members: vec![
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifestMember {
                    endpoint: "https://witness-a.example/v1/final".into(),
                    witness_id: "witness-a".into(),
                    witness_public_key: Some(key(2)),
                    witness_trust_state: None,
                    bearer_token_env: Some("WITNESS_A_TOKEN".into()),
                    timeout_seconds: 30,
                },
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumManifestMember {
                    endpoint: "https://witness-b.example/v1/final".into(),
                    witness_id: "witness-b".into(),
                    witness_public_key: Some(key(3)),
                    witness_trust_state: None,
                    bearer_token_env: None,
                    timeout_seconds: 60,
                },
            ],
        }
    }

    #[test]
    fn closes_and_canonicalizes_bounded_parallel_witness_manifests() {
        let manifest = manifest();
        let source =
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(&manifest)
                .unwrap();
        assert_eq!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(&source).unwrap(),
            manifest
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest_json_schema()["additionalProperties"],
            false
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest_json_schema()["properties"]
                ["members"]["items"]["additionalProperties"],
            false
        );
        assert!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(
                &serde_json::to_vec(&manifest).unwrap()
            )
            .is_err()
        );

        let mut unordered = manifest.clone();
        unordered.members.reverse();
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(&unordered)
                .is_err()
        );
        let mut repeated_key = manifest.clone();
        repeated_key.members[1].witness_public_key =
            repeated_key.members[0].witness_public_key.clone();
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(&repeated_key)
                .is_err()
        );
        let mut serial = manifest.clone();
        serial.maximum_parallelism = 1;
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_manifest(&serial)
                .is_err()
        );
        assert!(
            validate_manifest_against_checkpoint_key(
                &manifest,
                &decode_hex::<32>(
                    manifest.members[0].witness_public_key.as_ref().unwrap(),
                    "test key"
                )
                .unwrap(),
            )
            .is_err()
        );
    }

    fn partial_report() -> RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport{
        let checkpoint_key = key(1);
        let witness_a_key = key(2);
        let witness_b_key = key(3);
        let witness =
            SignedRemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitness {
                schema_version: 1,
                checkpoint_sha256: "8".repeat(64),
                registry_id: "factory-registry".into(),
                generation: 5,
                receipt_quorum_checkpoint_sha256: "4".repeat(64),
                checkpoint_witness_receipt_quorum_checkpoint_sha256: "9".repeat(64),
                final_admission_log_id: "factory-receipts".into(),
                final_admission_log_entry_count: 2,
                final_admission_log_head_sha256: "5".repeat(64),
                final_admission_log_sha256: "6".repeat(64),
                witness_id: "witness-a".into(),
                witnessed_at_unix: 999,
                algorithm: "ed25519".into(),
                public_key: witness_a_key.clone(),
                signature: "0".repeat(128),
            };
        let response = render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
            &witness,
        )
        .unwrap();
        let compact_witness = serde_json::to_vec(&witness).unwrap();
        let receipt = RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: "remote-factory-release-final-checkpoint-witness-receipt-quorum-log-checkpoint-witness-https-v1".into(),
            endpoint: "https://witness-a.example/v1/final".into(),
            final_checkpoint_witness_receipt_quorum_report_sha256: "7".repeat(64),
            final_checkpoint_witness_receipt_quorum_report_source_sha256: "1".repeat(64),
            registry_id: "factory-registry".into(),
            generation: 5,
            registry_checkpoint_sha256: "3".repeat(64),
            receipt_quorum_checkpoint_sha256: "4".repeat(64),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: "9".repeat(64),
            final_admission_log_id: "factory-receipts".into(),
            final_admission_log_entry_count: 2,
            final_admission_log_head_sha256: "5".repeat(64),
            final_admission_log_sha256: "6".repeat(64),
            final_admission_log_source_sha256: "2".repeat(64),
            checkpoint_sha256: "8".repeat(64),
            checkpoint_source_sha256: "3".repeat(64),
            checkpoint_public_key: checkpoint_key.clone(),
            request_sha256: "a".repeat(64),
            response_sha256: sha256(&response),
            response_bytes: response.len() as u64,
            witness_sha256: sha256(&compact_witness),
            evaluated_at_unix: 1_000,
            witness_id: "witness-a".into(),
            witness_public_key: witness_a_key.clone(),
            witness_key_trust_state_sha256: None,
            witness_key_generation: None,
            witnessed_at_unix: 999,
            verified: true,
        };
        let quorum = RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumReport {
            schema_version: 1,
            status: "insufficient_witnesses".into(),
            checkpoint_sha256: "8".repeat(64),
            registry_id: "factory-registry".into(),
            generation: 5,
            receipt_quorum_checkpoint_sha256: "4".repeat(64),
            checkpoint_witness_receipt_quorum_checkpoint_sha256: "9".repeat(64),
            final_admission_log_id: "factory-receipts".into(),
            final_admission_log_entry_count: 2,
            final_admission_log_head_sha256: "5".repeat(64),
            final_admission_log_sha256: "6".repeat(64),
            evaluated_at_unix: 1_000,
            minimum_witnesses: 2,
            valid_witnesses: 1,
            witness_ids: vec!["witness-a".into()],
            witness_public_keys: vec![witness_a_key.clone()],
            quorum_met: false,
        };
        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessQuorumAcquisitionReport {
            schema_version: 1,
            protocol: PROTOCOL.into(),
            manifest_sha256: "f".repeat(64),
            final_checkpoint_witness_receipt_quorum_report_source_sha256: "1".repeat(64),
            final_admission_log_source_sha256: "2".repeat(64),
            checkpoint_source_sha256: "3".repeat(64),
            checkpoint_public_key: checkpoint_key,
            evaluated_at_unix: 1_000,
            minimum_witnesses: 2,
            maximum_parallelism: 2,
            requested_witnesses: 2,
            verified_witnesses: 1,
            failed_witnesses: 1,
            members: vec![
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember {
                    endpoint: "https://witness-a.example/v1/final".into(),
                    witness_id: "witness-a".into(),
                    witness_public_key: witness_a_key,
                    witness_key_trust_state_sha256: None,
                    witness_key_generation: None,
                    status: RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Verified,
                    failure_code: None,
                    witness: Some(witness),
                    receipt: Some(receipt),
                },
                RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionMember {
                    endpoint: "https://witness-b.example/v1/final".into(),
                    witness_id: "witness-b".into(),
                    witness_public_key: witness_b_key,
                    witness_key_trust_state_sha256: None,
                    witness_key_generation: None,
                    status: RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionStatus::Failed,
                    failure_code: Some(
                        RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::Transport,
                    ),
                    witness: None,
                    receipt: None,
                },
            ],
            quorum,
            quorum_met: false,
        }
    }

    #[test]
    fn retains_only_closed_verified_successes_and_coarse_partial_failures() {
        assert_eq!(
            classify_failure(
                "remote final witness HTTPS request failed: http status: 503 Service Unavailable"
            ),
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::HttpStatus
        );
        assert_eq!(
            classify_failure("remote final witness HTTPS request failed: io: Connection refused"),
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::Transport
        );
        assert_eq!(
            classify_failure(
                "remote factory final checkpoint witness identity does not match the requested identity"
            ),
            RemoteFactoryReleaseFinalCheckpointWitnessReceiptQuorumLogCheckpointWitnessAcquisitionFailureCode::IdentityMismatch
        );
        let report = partial_report();
        let source =
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &report,
            )
            .unwrap();
        assert_eq!(
            parse_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &source
            )
            .unwrap(),
            report
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report_json_schema()
                ["additionalProperties"],
            false
        );
        assert_eq!(
            remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report_json_schema()
                ["properties"]["members"]["items"]["additionalProperties"],
            false
        );

        let mut leaked_failure = report.clone();
        leaked_failure.members[1].witness = leaked_failure.members[0].witness.clone();
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &leaked_failure
            )
            .is_err()
        );
        let mut wrong_count = report.clone();
        wrong_count.verified_witnesses = 2;
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &wrong_count
            )
            .is_err()
        );
        let mut exhausted_trust = report.clone();
        exhausted_trust.members[1].witness_key_trust_state_sha256 = Some("9".repeat(64));
        exhausted_trust.members[1].witness_key_generation =
            Some(MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION + 1);
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &exhausted_trust
            )
            .is_err()
        );
        let mut repeated_request = report.clone();
        let mut second = repeated_request.members[0].clone();
        second.endpoint = "https://witness-b.example/v1/final".into();
        second.witness_id = "witness-b".into();
        second.witness_public_key = key(3);
        let second_witness = second.witness.as_mut().unwrap();
        second_witness.witness_id = second.witness_id.clone();
        second_witness.public_key = second.witness_public_key.clone();
        let second_response = render_signed_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness(
            second_witness,
        )
        .unwrap();
        let second_compact = serde_json::to_vec(second_witness).unwrap();
        let second_receipt = second.receipt.as_mut().unwrap();
        second_receipt.endpoint = second.endpoint.clone();
        second_receipt.witness_id = second.witness_id.clone();
        second_receipt.witness_public_key = second.witness_public_key.clone();
        second_receipt.response_sha256 = sha256(&second_response);
        second_receipt.response_bytes = second_response.len() as u64;
        second_receipt.witness_sha256 = sha256(&second_compact);
        repeated_request.members[1] = second;
        repeated_request.verified_witnesses = 2;
        repeated_request.failed_witnesses = 0;
        repeated_request.quorum.status = "witness_quorum_met".into();
        repeated_request.quorum.valid_witnesses = 2;
        repeated_request.quorum.witness_ids = vec!["witness-a".into(), "witness-b".into()];
        repeated_request.quorum.witness_public_keys = vec![key(2), key(3)];
        repeated_request.quorum.quorum_met = true;
        repeated_request.quorum_met = true;
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &repeated_request
            )
            .is_err()
        );
        repeated_request.members[1]
            .receipt
            .as_mut()
            .unwrap()
            .request_sha256 = "b".repeat(64);
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &repeated_request
            )
            .is_ok()
        );
        let mut reordered = report;
        reordered.members.reverse();
        assert!(
            render_remote_factory_release_final_checkpoint_witness_receipt_quorum_log_checkpoint_witness_quorum_acquisition_report(
                &reordered
            )
            .is_err()
        );
    }
}
