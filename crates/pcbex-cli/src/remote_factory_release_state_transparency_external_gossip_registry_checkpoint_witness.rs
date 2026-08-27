//! Bounded remote witnesses for portable factory-release registry checkpoints.
//!
//! The v1.501 boundary sends one accepted v1.500 checkpoint trust state over a
//! bounded HTTPS adapter. The returned canonical witness is immediately
//! verified against the complete local registry history and either a directly
//! pinned key or a generation-chained witness trust state. A hash-bound
//! transport receipt records exactly which local history, request, and response
//! were used. This remains selected-witness evidence: it does not establish
//! global non-equivocation, trusted time, endpoint legal identity, or
//! independent witness operation.

use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::factory_release_state_transparency_external_gossip_registry::{
    MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION,
    parse_factory_release_state_transparency_external_gossip_organization_registry_history,
};
use crate::factory_release_state_transparency_external_gossip_registry_checkpoint::{
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
    FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint,
    factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key,
    parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state,
    parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state,
    parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness,
    signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256,
    verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses,
};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};

const PROTOCOL: &str = "pcbex-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-v1";
const ADAPTER: &str = "remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-https-v1";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_TIMESTAMP: u64 = 999_999_999_999_999;
pub(crate) const MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_BYTES: u64 =
    64 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteRegistryHistoryCheckpointWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    checkpoint_trust_state:
        &'a FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointTrustState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt
{
    pub(crate) schema_version: u32,
    pub(crate) adapter: String,
    pub(crate) endpoint: String,
    pub(crate) registry_id: String,
    pub(crate) generation: u64,
    pub(crate) history_sha256: String,
    pub(crate) checkpoint_sha256: String,
    pub(crate) checkpoint_trust_state_sha256: String,
    pub(crate) request_sha256: String,
    pub(crate) response_sha256: String,
    pub(crate) response_bytes: u64,
    pub(crate) witness_sha256: String,
    pub(crate) evaluated_at_unix: u64,
    pub(crate) witness_id: String,
    pub(crate) witness_public_key: String,
    pub(crate) witness_key_trust_state_sha256: Option<String>,
    pub(crate) witness_key_generation: Option<u64>,
    pub(crate) witnessed_at_unix: u64,
    pub(crate) verified: bool,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
>{
    request_remote_witness(
        history_source,
        checkpoint_trust_state_source,
        endpoint,
        trusted_public_key,
        None,
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_with_trust_state(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    endpoint: &str,
    witness_key_trust_state_source: &[u8],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
>{
    let trust_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state(
            witness_key_trust_state_source,
        )?;
    let trusted_public_key =
        factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            &trust_state,
        )?;
    request_remote_witness(
        history_source,
        checkpoint_trust_state_source,
        endpoint,
        &trusted_public_key,
        Some((&trust_state, sha256(witness_key_trust_state_source))),
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    verify_remote_receipt(
        receipt,
        history_source,
        checkpoint_trust_state_source,
        response_bytes,
        trusted_public_key,
        None,
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_with_trust_state(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_bytes: &[u8],
    witness_key_trust_state_source: &[u8],
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    let trust_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trust_state(
            witness_key_trust_state_source,
        )?;
    let trusted_public_key =
        factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            &trust_state,
        )?;
    verify_remote_receipt(
        receipt,
        history_source,
        checkpoint_trust_state_source,
        response_bytes,
        &trusted_public_key,
        Some((&trust_state, sha256(witness_key_trust_state_source))),
        evaluated_at_unix,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_remote_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    response_bytes: &[u8],
    trusted_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
        String,
    )>,
    evaluated_at_unix: u64,
) -> Result<
    SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
    String,
> {
    validate_remote_receipt(receipt)?;
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release registry history checkpoint witness admission time is outside its bound"
                .into(),
        );
    }
    if evaluated_at_unix < receipt.evaluated_at_unix {
        return Err(
            "remote factory release registry history checkpoint witness receipt is future-dated at admission"
                .into(),
        );
    }
    validate_nonweak_public_key(trusted_public_key, "trusted registry history witness key")?;

    let history =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history(
            history_source,
        )?;
    let checkpoint_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
            checkpoint_trust_state_source,
        )?;
    let reconstructed =
        accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history,
            &checkpoint_state.signed_checkpoint,
            None,
            checkpoint_state.accepted_at_unix,
        )?;
    if reconstructed != checkpoint_state {
        return Err(
            "factory release registry history checkpoint trust state does not match the complete history"
                .into(),
        );
    }

    let request_bytes = serde_json::to_vec(&RemoteRegistryHistoryCheckpointWitnessRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        checkpoint_trust_state: &checkpoint_state,
    })
    .map_err(|error| {
        format!(
            "serializing remote factory release registry history checkpoint witness request: {error}"
        )
    })?;
    if receipt.registry_id != checkpoint_state.registry_id
        || receipt.generation != checkpoint_state.accepted_generation
        || receipt.history_sha256 != sha256(history_source)
        || receipt.checkpoint_sha256 != checkpoint_state.checkpoint_sha256
        || receipt.checkpoint_trust_state_sha256 != sha256(checkpoint_trust_state_source)
        || receipt.request_sha256 != sha256(&request_bytes)
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt is bound to different retained evidence"
                .into(),
        );
    }
    if response_bytes.is_empty()
        || response_bytes.len() as u64 > MAX_RESPONSE_BYTES
        || receipt.response_bytes != response_bytes.len() as u64
        || receipt.response_sha256 != sha256(response_bytes)
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt response binding is invalid"
                .into(),
        );
    }
    let witness =
        parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            response_bytes,
        )?;
    if receipt.witness_sha256
        != signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256(
            &witness,
        )?
        || receipt.witness_id != witness.witness_id
        || receipt.witness_public_key != witness.public_key
        || receipt.witnessed_at_unix != witness.witnessed_at_unix
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt describes different witness evidence"
                .into(),
        );
    }
    let expected_trust_binding = witness_key_trust_state
        .as_ref()
        .map(|(state, digest)| (Some(digest.clone()), Some(state.generation)))
        .unwrap_or((None, None));
    if (
        receipt.witness_key_trust_state_sha256.clone(),
        receipt.witness_key_generation,
    ) != expected_trust_binding
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt trust binding is invalid"
                .into(),
        );
    }
    if let Some((trust_state, _)) = &witness_key_trust_state
        && witness.witness_id != trust_state.witness_id
    {
        return Err(
            "remote factory release registry history checkpoint witness identity does not match its trust state"
                .into(),
        );
    }

    let trusted_witnesses = vec![(witness.witness_id.clone(), *trusted_public_key)];
    let report =
        verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &history,
            &checkpoint_state.signed_checkpoint,
            std::slice::from_ref(&witness),
            &trusted_witnesses,
            2,
            evaluated_at_unix,
        )?;
    if report.valid_witnesses != 1 || report.quorum_met {
        return Err(
            "remote factory release registry history checkpoint witness admission produced an invalid single-witness result"
                .into(),
        );
    }
    Ok(witness)
}

#[allow(clippy::too_many_arguments)]
fn request_remote_witness(
    history_source: &[u8],
    checkpoint_trust_state_source: &[u8],
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    witness_key_trust_state: Option<(
        &FactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
        String,
    )>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
>{
    if !(1..=600).contains(&timeout_seconds) {
        return Err(
            "remote factory release registry history checkpoint witness timeout must be between 1 and 600 seconds"
                .into(),
        );
    }
    if evaluated_at_unix > MAX_TIMESTAMP {
        return Err(
            "remote factory release registry history checkpoint witness evaluation time is outside its bound"
                .into(),
        );
    }
    validate_nonweak_public_key(trusted_public_key, "trusted registry history witness key")?;
    validate_endpoint(endpoint, allow_http_loopback)?;

    // Audit before performing network I/O. The equality check proves that the
    // supplied trust state is the canonical acceptance result for this exact
    // complete history and embedded retained-root checkpoint.
    let history =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history(
            history_source,
        )?;
    let checkpoint_state =
        parse_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_trust_state(
            checkpoint_trust_state_source,
        )?;
    let reconstructed =
        accept_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint(
            &history,
            &checkpoint_state.signed_checkpoint,
            None,
            checkpoint_state.accepted_at_unix,
        )?;
    if reconstructed != checkpoint_state {
        return Err(
            "factory release registry history checkpoint trust state does not match the complete history"
                .into(),
        );
    }

    let request = RemoteRegistryHistoryCheckpointWitnessRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        checkpoint_trust_state: &checkpoint_state,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        format!("serializing remote factory release registry history checkpoint witness request: {error}")
    })?;
    let request_sha256 = sha256(&request_bytes);
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .build();
    let agent: ureq::Agent = config.into();
    let mut call = agent
        .post(endpoint)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json");
    if let Some(variable) = bearer_token_env {
        validate_env_name(variable)?;
        let token = env::var(variable).map_err(|_| {
            format!(
                "remote factory release registry history checkpoint witness bearer-token environment {variable} is unset"
            )
        })?;
        if token.trim().is_empty() {
            return Err(format!(
                "remote factory release registry history checkpoint witness bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call.send(request_bytes).map_err(|error| {
        format!(
            "remote factory release registry history checkpoint witness HTTPS request failed: {error}"
        )
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote factory release registry history checkpoint witness returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err(
            "remote factory release registry history checkpoint witness response Content-Type must be application/json"
                .into(),
        );
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| {
            format!(
                "reading bounded remote factory release registry history checkpoint witness response: {error}"
            )
        })?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "remote factory release registry history checkpoint witness response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let witness =
        parse_signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness(
            &response_bytes,
        )?;
    if let Some((trust_state, _)) = &witness_key_trust_state
        && witness.witness_id != trust_state.witness_id
    {
        return Err(
            "remote factory release registry history checkpoint witness identity does not match its trust state"
                .into(),
        );
    }
    let trusted_witnesses = vec![(witness.witness_id.clone(), *trusted_public_key)];
    let report =
        verify_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witnesses(
            &history,
            &checkpoint_state.signed_checkpoint,
            std::slice::from_ref(&witness),
            &trusted_witnesses,
            2,
            evaluated_at_unix,
        )?;
    if report.valid_witnesses != 1 || report.quorum_met {
        return Err(
            "remote factory release registry history checkpoint witness verification produced an invalid single-witness result"
                .into(),
        );
    }

    let (witness_key_trust_state_sha256, witness_key_generation) = witness_key_trust_state
        .map(|(state, digest)| (Some(digest), Some(state.generation)))
        .unwrap_or((None, None));
    let receipt = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt {
        schema_version: 1,
        adapter: ADAPTER.into(),
        endpoint: endpoint.into(),
        registry_id: checkpoint_state.registry_id.clone(),
        generation: checkpoint_state.accepted_generation,
        history_sha256: sha256(history_source),
        checkpoint_sha256: checkpoint_state.checkpoint_sha256.clone(),
        checkpoint_trust_state_sha256: sha256(checkpoint_trust_state_source),
        request_sha256,
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        witness_sha256:
            signed_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_sha256(
                &witness,
            )?,
        evaluated_at_unix,
        witness_id: witness.witness_id.clone(),
        witness_public_key: witness.public_key.clone(),
        witness_key_trust_state_sha256,
        witness_key_generation,
        witnessed_at_unix: witness.witnessed_at_unix,
        verified: true,
    };
    validate_remote_receipt(&receipt)?;
    Ok((witness, receipt))
}

pub(crate) fn render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
) -> Result<Vec<u8>, String> {
    validate_remote_receipt(receipt)?;
    render_bounded(
        receipt,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory release registry history checkpoint witness receipt",
    )
}

pub(crate) fn parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
    source: &[u8],
) -> Result<
    RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
    String,
>{
    let receipt = parse_canonical(
        source,
        MAX_REMOTE_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_ORGANIZATION_REGISTRY_HISTORY_CHECKPOINT_WITNESS_RECEIPT_BYTES,
        "remote factory release registry history checkpoint witness receipt",
    )?;
    validate_remote_receipt(&receipt)?;
    Ok(receipt)
}

pub(crate) fn remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_json_schema()
-> Value {
    let digest = digest_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-factory-release-state-transparency-external-gossip-organization-registry-history-checkpoint-witness-receipt-v1.json",
        "title": "pcbex remote factory-release registry-history checkpoint witness receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "registry_id", "generation",
            "history_sha256", "checkpoint_sha256", "checkpoint_trust_state_sha256",
            "request_sha256", "response_sha256", "response_bytes", "witness_sha256",
            "evaluated_at_unix", "witness_id", "witness_public_key",
            "witness_key_trust_state_sha256", "witness_key_generation",
            "witnessed_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": ADAPTER},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "registry_id": slug_schema(),
            "generation": {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION},
            "history_sha256": digest.clone(),
            "checkpoint_sha256": digest.clone(),
            "checkpoint_trust_state_sha256": digest.clone(),
            "request_sha256": digest.clone(),
            "response_sha256": digest.clone(),
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "witness_sha256": digest.clone(),
            "evaluated_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "witness_id": slug_schema(),
            "witness_public_key": digest.clone(),
            "witness_key_trust_state_sha256": {"oneOf": [{"type": "null"}, digest]},
            "witness_key_generation": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0, "maximum": MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION}
                ]
            },
            "witnessed_at_unix": {"type": "integer", "minimum": 0, "maximum": MAX_TIMESTAMP},
            "verified": {"const": true}
        }
    })
}

fn validate_remote_receipt(
    receipt: &RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1
        || receipt.adapter != ADAPTER
        || !receipt.verified
        || receipt.generation
            > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
        || receipt.response_bytes == 0
        || receipt.response_bytes > MAX_RESPONSE_BYTES
        || receipt.witnessed_at_unix > receipt.evaluated_at_unix
        || receipt.evaluated_at_unix > MAX_TIMESTAMP
    {
        return Err(
            "remote factory release registry history checkpoint witness receipt invariants are invalid"
                .into(),
        );
    }
    validate_endpoint(&receipt.endpoint, true)?;
    validate_slug(&receipt.registry_id, "registry id")?;
    validate_slug(&receipt.witness_id, "registry history witness id")?;
    for (digest, label) in [
        (&receipt.history_sha256, "registry history SHA-256"),
        (
            &receipt.checkpoint_sha256,
            "registry history checkpoint SHA-256",
        ),
        (
            &receipt.checkpoint_trust_state_sha256,
            "registry history checkpoint trust-state SHA-256",
        ),
        (&receipt.request_sha256, "remote witness request SHA-256"),
        (&receipt.response_sha256, "remote witness response SHA-256"),
        (&receipt.witness_sha256, "registry history witness SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    let public_key = decode_hex::<32>(&receipt.witness_public_key, "witness public key")?;
    validate_nonweak_public_key(&public_key, "witness public key")?;
    match (
        &receipt.witness_key_trust_state_sha256,
        receipt.witness_key_generation,
    ) {
        (None, None) => {}
        (Some(digest), Some(generation)) => {
            validate_digest(digest, "witness key trust-state SHA-256")?;
            if generation
                > MAX_FACTORY_RELEASE_STATE_TRANSPARENCY_EXTERNAL_GOSSIP_REGISTRY_GENERATION
            {
                return Err("remote witness receipt key generation is outside its bound".into());
            }
        }
        _ => return Err("remote witness receipt trust-state binding is incomplete".into()),
    }
    Ok(())
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

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint.parse().map_err(|error| {
        format!(
            "invalid remote factory release registry history checkpoint witness endpoint: {error}"
        )
    })?;
    let scheme = uri.scheme_str().ok_or_else(|| {
        "remote factory release registry history checkpoint witness endpoint must have a scheme"
            .to_string()
    })?;
    if uri.authority().is_none() {
        return Err(
            "remote factory release registry history checkpoint witness endpoint must have an authority"
                .into(),
        );
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(
            "remote factory release registry history checkpoint witness endpoint must not contain userinfo"
                .into(),
        );
    }
    if uri.query().is_some() {
        return Err(
            "remote factory release registry history checkpoint witness endpoint must not contain a query"
                .into(),
        );
    }
    if scheme == "https" {
        return Ok(());
    }
    let host = uri.host().unwrap_or_default();
    let loopback = host == "localhost"
        || host == "127.0.0.1"
        || host == "[::1]"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if scheme == "http" && allow_http_loopback && loopback {
        Ok(())
    } else {
        Err(
            "remote factory release registry history checkpoint witness endpoint must use HTTPS"
                .into(),
        )
    }
}

fn validate_env_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if !matches!(first, Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("bearer-token environment name is invalid".into());
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().enumerate().all(|(index, byte)| match byte {
            b'a'..=b'z' | b'0'..=b'9' => true,
            b'.' | b'-' => index != 0,
            _ => false,
        })
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    decode_hex::<32>(value, label).map(|_| ())
}

fn validate_nonweak_public_key(value: &[u8; 32], label: &str) -> Result<(), String> {
    let key =
        VerifyingKey::from_bytes(value).map_err(|error| format!("invalid {label}: {error}"))?;
    if key.is_weak() {
        return Err(format!("{label} is weak"));
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(format!(
            "{label} must contain {} lowercase hexadecimal digits",
            N * 2
        ));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
}

fn sha256(source: &[u8]) -> String {
    hex::encode(Sha256::digest(source))
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn closes_receipts_and_rejects_unsafe_transport_configuration() {
        assert_eq!(
            remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt_json_schema()["additionalProperties"],
            false
        );
        assert!(
            validate_endpoint(
                "https://witness.example/v1/factory-registry-history-checkpoint",
                false
            )
            .is_ok()
        );
        assert!(
            validate_endpoint(
                "https://witness.example/v1/factory-registry-history-checkpoint?token=secret",
                false
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "https://secret@witness.example/v1/factory-registry-history-checkpoint",
                false
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "http://example.com/v1/factory-registry-history-checkpoint",
                true
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "http://127.0.0.1:1234/v1/factory-registry-history-checkpoint",
                false
            )
            .is_err()
        );
        assert!(
            validate_endpoint(
                "http://127.0.0.1:1234/v1/factory-registry-history-checkpoint",
                true
            )
            .is_ok()
        );
        assert!(validate_env_name("PCBEX_FACTORY_REGISTRY_WITNESS_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
    }

    #[test]
    fn round_trips_only_exact_canonical_complete_receipts() {
        let public_key = hex::encode(SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes());
        let receipt = RemoteFactoryReleaseStateTransparencyExternalGossipOrganizationRegistryHistoryCheckpointWitnessReceipt {
            schema_version: 1,
            adapter: ADAPTER.into(),
            endpoint: "https://witness.example/v1/factory-registry-history-checkpoint".into(),
            registry_id: "factory-registry".into(),
            generation: 5,
            history_sha256: "1".repeat(64),
            checkpoint_sha256: "2".repeat(64),
            checkpoint_trust_state_sha256: "3".repeat(64),
            request_sha256: "4".repeat(64),
            response_sha256: "5".repeat(64),
            response_bytes: 512,
            witness_sha256: "6".repeat(64),
            evaluated_at_unix: 1_000,
            witness_id: "witness-a".into(),
            witness_public_key: public_key,
            witness_key_trust_state_sha256: Some("7".repeat(64)),
            witness_key_generation: Some(3),
            witnessed_at_unix: 999,
            verified: true,
        };
        let source = render_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
            &receipt,
        )
        .unwrap();
        assert_eq!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                &source,
            )
            .unwrap(),
            receipt
        );

        let compact = serde_json::to_vec(&receipt).unwrap();
        assert!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                &compact,
            )
            .is_err()
        );
        let duplicate = String::from_utf8(source.clone()).unwrap().replacen(
            "  \"schema_version\": 1,",
            "  \"schema_version\": 1,\n  \"schema_version\": 1,",
            1,
        );
        assert!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                duplicate.as_bytes(),
            )
            .is_err()
        );
        let unknown =
            String::from_utf8(source)
                .unwrap()
                .replacen("{\n", "{\n  \"unexpected\": true,\n", 1);
        assert!(
            parse_remote_factory_release_state_transparency_external_gossip_organization_registry_history_checkpoint_witness_receipt(
                unknown.as_bytes(),
            )
            .is_err()
        );

        let mut incomplete = receipt;
        incomplete.witness_key_generation = None;
        assert!(validate_remote_receipt(&incomplete).is_err());
    }
}
