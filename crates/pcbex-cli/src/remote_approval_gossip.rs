use pcbex_kicad::{
    ApprovalLogAnchorProof, ApprovalLogGossipObservation, SignedApprovalPublicLogTreeHead,
    approval_public_log_tree_head_sha256, validate_approval_log_anchor_proof,
    validate_approval_log_gossip_observation, verify_approval_log_gossip_receipt,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};

const PROTOCOL: &str = "pcbex-approval-public-log-gossip-v1";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteApprovalLogGossipRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    log_id: &'a str,
    local_tree_head: &'a SignedApprovalPublicLogTreeHead,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteApprovalLogGossipReceipt {
    pub schema_version: u32,
    pub adapter: String,
    pub endpoint: String,
    pub log_id: String,
    pub local_tree_head_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub evaluated_at_unix: u64,
    pub organization_id: String,
    pub observer_id: String,
    pub observer_public_key: String,
    pub gossip_receipt_sha256: String,
    pub received_at_unix: u64,
    pub expires_at_unix: u64,
    pub verified: bool,
}

#[allow(clippy::too_many_arguments)]
pub fn request_remote_approval_log_gossip(
    local_anchor: &ApprovalLogAnchorProof,
    endpoint: &str,
    trusted_log_public_key: &[u8; 32],
    organization_id: &str,
    trusted_observer_id: &str,
    trusted_observer_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<(ApprovalLogGossipObservation, RemoteApprovalLogGossipReceipt), String> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err("remote approval gossip timeout must be between 1 and 600 seconds".into());
    }
    validate_approval_log_anchor_proof(local_anchor)?;
    validate_slug(organization_id, "remote approval gossip organization id")?;
    validate_endpoint(endpoint, allow_http_loopback)?;
    let request = RemoteApprovalLogGossipRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        log_id: &local_anchor.tree_head.log_id,
        local_tree_head: &local_anchor.tree_head,
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("serializing remote approval gossip request: {error}"))?;
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
            format!("remote approval gossip bearer-token environment {variable} is unset")
        })?;
        if token.trim().is_empty() {
            return Err(format!(
                "remote approval gossip bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .send(request_bytes.clone())
        .map_err(|error| format!("remote approval gossip HTTPS request failed: {error}"))?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote approval gossip returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err("remote approval gossip response Content-Type must be application/json".into());
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| format!("reading bounded remote approval gossip response: {error}"))?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "remote approval gossip response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let observation: ApprovalLogGossipObservation = serde_json::from_slice(&response_bytes)
        .map_err(|error| format!("invalid remote approval gossip response JSON: {error}"))?;
    validate_approval_log_gossip_observation(&observation)?;
    let report = verify_approval_log_gossip_receipt(
        local_anchor,
        &observation.receipt,
        observation.consistency_proof.as_ref(),
        trusted_log_public_key,
        trusted_observer_id,
        trusted_observer_public_key,
        evaluated_at_unix,
    )?;
    Ok((
        observation,
        RemoteApprovalLogGossipReceipt {
            schema_version: 1,
            adapter: "remote-approval-public-log-gossip-https-v1".into(),
            endpoint: endpoint.into(),
            log_id: local_anchor.tree_head.log_id.clone(),
            local_tree_head_sha256: approval_public_log_tree_head_sha256(&local_anchor.tree_head)?,
            request_sha256,
            response_sha256: sha256(&response_bytes),
            response_bytes: response_bytes.len() as u64,
            evaluated_at_unix,
            organization_id: organization_id.into(),
            observer_id: trusted_observer_id.into(),
            observer_public_key: hex_encode(trusted_observer_public_key),
            gossip_receipt_sha256: report.gossip_receipt_sha256,
            received_at_unix: report.received_at_unix,
            expires_at_unix: report.expires_at_unix,
            verified: true,
        },
    ))
}

pub fn remote_approval_log_gossip_receipt_json_schema() -> Value {
    let digest = json!({"type": "string", "pattern": "^[0-9a-f]{64}$"});
    let slug = json!({
        "type": "string", "minLength": 1, "maxLength": 128,
        "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
    });
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/remote-approval-log-gossip-receipt-v1.json",
        "title": "pcbex remote approval public-log gossip HTTPS receipt",
        "type": "object", "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "log_id",
            "local_tree_head_sha256", "request_sha256", "response_sha256",
            "response_bytes", "evaluated_at_unix", "organization_id",
            "observer_id", "observer_public_key", "gossip_receipt_sha256",
            "received_at_unix", "expires_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": "remote-approval-public-log-gossip-https-v1"},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "log_id": slug.clone(),
            "local_tree_head_sha256": digest.clone(),
            "request_sha256": digest.clone(),
            "response_sha256": digest.clone(),
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "organization_id": slug.clone(),
            "observer_id": slug,
            "observer_public_key": digest.clone(),
            "gossip_receipt_sha256": digest,
            "received_at_unix": {"type": "integer", "minimum": 0},
            "expires_at_unix": {"type": "integer", "minimum": 1},
            "verified": {"const": true}
        }
    })
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint
        .parse()
        .map_err(|error| format!("invalid remote approval gossip endpoint: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "remote approval gossip endpoint must have a scheme".to_string())?;
    if uri.authority().is_none()
        || uri
            .authority()
            .is_some_and(|authority| authority.as_str().contains('@'))
        || uri.query().is_some()
    {
        return Err("remote approval gossip endpoint is not allowed".into());
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
        Err("remote approval gossip endpoint must use HTTPS".into())
    }
}

fn validate_env_name(value: &str) -> Result<(), String> {
    if !value.is_empty()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_uppercase() || (index > 0 && byte.is_ascii_digit())
        })
    {
        Ok(())
    } else {
        Err("remote approval gossip bearer-token environment name is invalid".into())
    }
}

fn validate_slug(value: &str, label: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit());
    valid
        .then_some(())
        .ok_or_else(|| format!("invalid {label}"))
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_policy_is_fail_closed() {
        assert!(validate_endpoint("https://observer.example/v1/gossip", false).is_ok());
        assert!(validate_endpoint("http://127.0.0.1:8080/gossip", true).is_ok());
        assert!(validate_endpoint("http://observer.example/gossip", true).is_err());
        assert!(validate_endpoint("https://user@observer.example/gossip", false).is_err());
        assert!(validate_endpoint("https://observer.example/gossip?token=x", false).is_err());
    }

    #[test]
    fn receipt_schema_is_closed() {
        assert_eq!(
            remote_approval_log_gossip_receipt_json_schema()["additionalProperties"],
            false
        );
    }
}
