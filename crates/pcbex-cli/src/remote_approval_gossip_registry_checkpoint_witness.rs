use ed25519_dalek::VerifyingKey;
use pcbex_kicad::{
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
    approval_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key,
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state,
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state,
    verify_approval_log_gossip_organization_registry_history_checkpoint_witness_for_trust_state,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};

const PROTOCOL: &str =
    "pcbex-approval-public-log-gossip-organization-registry-history-checkpoint-witness-v1";
const ADAPTER: &str = "remote-approval-gossip-registry-history-checkpoint-witness-https-v1";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteApprovalRegistryHistoryCheckpointWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    checkpoint_trust_state: &'a ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalRegistryHistoryCheckpointWitnessReceipt {
    pub schema_version: u32,
    pub adapter: String,
    pub endpoint: String,
    pub registry_id: String,
    pub generation: u64,
    pub checkpoint_sha256: String,
    pub checkpoint_trust_state_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub evaluated_at_unix: u64,
    pub witness_id: String,
    pub witness_public_key: String,
    pub witness_key_trust_state_sha256: Option<String>,
    pub witness_key_generation: Option<u64>,
    pub witnessed_at_unix: u64,
    pub verified: bool,
}

pub fn remote_approval_registry_history_checkpoint_witness_receipt_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-approval-gossip-registry-history-checkpoint-witness-receipt-v1.json",
        "title": "pcbex remote approval registry-history checkpoint witness HTTPS receipt",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "registry_id", "generation",
            "checkpoint_sha256", "checkpoint_trust_state_sha256", "request_sha256",
            "response_sha256", "response_bytes", "evaluated_at_unix", "witness_id",
            "witness_public_key", "witness_key_trust_state_sha256",
            "witness_key_generation", "witnessed_at_unix", "verified"
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
            "generation": {"type": "integer", "minimum": 0},
            "checkpoint_sha256": digest_schema(),
            "checkpoint_trust_state_sha256": digest_schema(),
            "request_sha256": digest_schema(),
            "response_sha256": digest_schema(),
            "response_bytes": {
                "type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES
            },
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "witness_id": slug_schema(),
            "witness_public_key": key_schema(),
            "witness_key_trust_state_sha256": {
                "oneOf": [{"type": "null"}, digest_schema()]
            },
            "witness_key_generation": {
                "oneOf": [
                    {"type": "null"},
                    {"type": "integer", "minimum": 0}
                ]
            },
            "witnessed_at_unix": {"type": "integer", "minimum": 0},
            "verified": {"const": true}
        }
    })
}

pub fn parse_remote_approval_registry_history_checkpoint_witness_receipt(
    source: &str,
) -> Result<RemoteApprovalRegistryHistoryCheckpointWitnessReceipt, String> {
    let receipt: RemoteApprovalRegistryHistoryCheckpointWitnessReceipt =
        serde_json::from_str(source)
            .map_err(|error| format!("invalid remote approval history witness receipt: {error}"))?;
    validate_remote_approval_registry_history_checkpoint_witness_receipt(&receipt)?;
    Ok(receipt)
}

pub fn validate_remote_approval_registry_history_checkpoint_witness_receipt(
    receipt: &RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
) -> Result<(), String> {
    if receipt.schema_version != 1
        || receipt.adapter != ADAPTER
        || !receipt.verified
        || receipt.response_bytes == 0
        || receipt.response_bytes > MAX_RESPONSE_BYTES
        || receipt.witnessed_at_unix > receipt.evaluated_at_unix
    {
        return Err("invalid remote approval history witness receipt invariants".into());
    }
    validate_endpoint(&receipt.endpoint, true)?;
    validate_slug(&receipt.registry_id, "approval registry id")?;
    for (digest, label) in [
        (&receipt.checkpoint_sha256, "checkpoint SHA-256"),
        (
            &receipt.checkpoint_trust_state_sha256,
            "checkpoint trust-state SHA-256",
        ),
        (&receipt.request_sha256, "request SHA-256"),
        (&receipt.response_sha256, "response SHA-256"),
    ] {
        validate_digest(digest, label)?;
    }
    validate_slug(&receipt.witness_id, "approval history witness id")?;
    let key = decode_hex::<32>(&receipt.witness_public_key, "witness public key")?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| format!("invalid approval history witness public key: {error}"))?;
    match (
        &receipt.witness_key_trust_state_sha256,
        receipt.witness_key_generation,
    ) {
        (None, None) => {}
        (Some(digest), Some(_)) => validate_digest(digest, "witness trust-state SHA-256")?,
        _ => return Err("remote approval witness trust-state binding is incomplete".into()),
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn request_remote_approval_registry_history_checkpoint_witness(
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
> {
    request_remote(
        checkpoint_state,
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
pub fn request_remote_approval_registry_history_checkpoint_witness_with_trust_state(
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    endpoint: &str,
    witness_trust_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointWitnessTrustState,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
> {
    validate_approval_log_gossip_organization_registry_history_checkpoint_witness_trust_state(
        witness_trust_state,
    )?;
    let key =
        approval_log_gossip_organization_registry_history_checkpoint_witness_trusted_public_key(
            witness_trust_state,
        )?;
    let encoded = serde_json::to_vec(witness_trust_state)
        .map_err(|error| format!("serializing approval witness trust state: {error}"))?;
    let result = request_remote(
        checkpoint_state,
        endpoint,
        &key,
        Some((sha256(&encoded), witness_trust_state.generation)),
        bearer_token_env,
        timeout_seconds,
        evaluated_at_unix,
        allow_http_loopback,
    )?;
    if result.0.witness_id != witness_trust_state.witness_id {
        return Err("remote approval history witness identity does not match trust state".into());
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn request_remote(
    checkpoint_state: &ApprovalLogGossipOrganizationRegistryHistoryCheckpointTrustState,
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    witness_trust_binding: Option<(String, u64)>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness,
        RemoteApprovalRegistryHistoryCheckpointWitnessReceipt,
    ),
    String,
> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err("remote approval history witness timeout must be 1..=600 seconds".into());
    }
    validate_approval_log_gossip_organization_registry_history_checkpoint_trust_state(
        checkpoint_state,
    )?;
    validate_endpoint(endpoint, allow_http_loopback)?;
    let request = RemoteApprovalRegistryHistoryCheckpointWitnessRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        checkpoint_trust_state: checkpoint_state,
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("serializing remote approval history request: {error}"))?;
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
        let token = env::var(variable)
            .map_err(|_| format!("bearer-token environment {variable} is unset"))?;
        if token.trim().is_empty() {
            return Err(format!("bearer-token environment {variable} is empty"));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .send(request_bytes.clone())
        .map_err(|error| format!("remote approval history HTTPS request failed: {error}"))?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote approval history witness returned HTTP {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err("remote approval history response must be application/json".into());
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| format!("reading bounded remote approval history response: {error}"))?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err("remote approval history response exceeds 1 MiB".into());
    }
    let witness: SignedApprovalLogGossipOrganizationRegistryHistoryCheckpointWitness =
        serde_json::from_slice(&response_bytes)
            .map_err(|error| format!("invalid remote approval history witness JSON: {error}"))?;
    verify_approval_log_gossip_organization_registry_history_checkpoint_witness_for_trust_state(
        checkpoint_state,
        &witness,
        trusted_public_key,
        evaluated_at_unix,
    )?;
    let checkpoint_bytes = serde_json::to_vec(checkpoint_state)
        .map_err(|error| format!("serializing approval checkpoint trust state: {error}"))?;
    let (trust_digest, trust_generation) = witness_trust_binding
        .map(|(digest, generation)| (Some(digest), Some(generation)))
        .unwrap_or((None, None));
    let receipt = RemoteApprovalRegistryHistoryCheckpointWitnessReceipt {
        schema_version: 1,
        adapter: ADAPTER.into(),
        endpoint: endpoint.into(),
        registry_id: checkpoint_state.registry_id.clone(),
        generation: checkpoint_state.accepted_generation,
        checkpoint_sha256: checkpoint_state.checkpoint_sha256.clone(),
        checkpoint_trust_state_sha256: sha256(&checkpoint_bytes),
        request_sha256: sha256(&request_bytes),
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        evaluated_at_unix,
        witness_id: witness.witness_id.clone(),
        witness_public_key: witness.public_key.clone(),
        witness_key_trust_state_sha256: trust_digest,
        witness_key_generation: trust_generation,
        witnessed_at_unix: witness.witnessed_at_unix,
        verified: true,
    };
    validate_remote_approval_registry_history_checkpoint_witness_receipt(&receipt)?;
    Ok((witness, receipt))
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint
        .parse()
        .map_err(|error| format!("invalid remote approval history endpoint: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "remote approval history endpoint requires a scheme".to_string())?;
    let authority = uri
        .authority()
        .ok_or_else(|| "remote approval history endpoint requires an authority".to_string())?;
    if authority.as_str().contains('@') || uri.query().is_some() {
        return Err("remote approval history endpoint forbids userinfo and query".into());
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
        Err("remote approval history witness endpoint must use HTTPS".into())
    }
}

fn validate_env_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    if !matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("bearer-token environment name is invalid".into());
    }
    Ok(())
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if valid {
        Ok(())
    } else {
        Err(format!("{label} is invalid"))
    }
}

fn validate_digest(value: &str, label: &str) -> Result<(), String> {
    decode_hex::<32>(value, label).map(|_| ())
}

fn decode_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be lowercase hexadecimal"));
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|error| format!("decoding {label}: {error}"))?;
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn slug_schema() -> Value {
    json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9._-]*$"
    })
}

fn digest_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

fn key_schema() -> Value {
    json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_receipts_and_rejects_unsafe_transport_configuration() {
        assert_eq!(
            remote_approval_registry_history_checkpoint_witness_receipt_json_schema()["additionalProperties"],
            false
        );
        assert!(validate_endpoint("https://witness.example/v1/history", false).is_ok());
        assert!(
            validate_endpoint("https://witness.example/v1/history?token=secret", false).is_err()
        );
        assert!(validate_endpoint("https://secret@witness.example/v1/history", false).is_err());
        assert!(validate_endpoint("http://example.com/v1/history", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/history", false).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/history", true).is_ok());
        assert!(validate_env_name("PCBEX_APPROVAL_HISTORY_WITNESS_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
    }
}
