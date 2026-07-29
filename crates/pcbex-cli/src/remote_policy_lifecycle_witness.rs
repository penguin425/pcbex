use crate::policy_lifecycle_checkpoint::{
    PolicyLifecycleTrustState, SignedPolicyLifecycleCheckpointWitness,
    validate_policy_lifecycle_trust_state, verify_policy_lifecycle_checkpoint_witness,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};

const PROTOCOL: &str = "pcbex-policy-lifecycle-checkpoint-witness-v1";
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct RemotePolicyLifecycleWitnessRequest<'a> {
    schema_version: u32,
    protocol: &'static str,
    trust_state: &'a PolicyLifecycleTrustState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePolicyLifecycleWitnessReceipt {
    pub schema_version: u32,
    pub adapter: String,
    pub endpoint: String,
    pub checkpoint_sha256: String,
    pub request_sha256: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub evaluated_at_unix: u64,
    pub witness_id: String,
    pub witness_public_key: String,
    pub observed_at_unix: u64,
    pub verified: bool,
}

pub fn remote_policy_lifecycle_witness_receipt_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/remote-policy-lifecycle-witness-receipt-v1.json",
        "title": "pcbex remote policy lifecycle witness HTTPS receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "checkpoint_sha256",
            "request_sha256", "response_sha256", "response_bytes",
            "evaluated_at_unix", "witness_id", "witness_public_key",
            "observed_at_unix", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": "remote-policy-lifecycle-witness-https-v1"},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "checkpoint_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "evaluated_at_unix": {"type": "integer", "minimum": 0},
            "witness_id": {
                "type": "string", "minLength": 1, "maxLength": 128,
                "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"
            },
            "witness_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "observed_at_unix": {"type": "integer", "minimum": 0},
            "verified": {"const": true}
        }
    })
}

pub fn request_remote_policy_lifecycle_witness(
    state: &PolicyLifecycleTrustState,
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    evaluated_at_unix: u64,
    allow_http_loopback: bool,
) -> Result<
    (
        SignedPolicyLifecycleCheckpointWitness,
        RemotePolicyLifecycleWitnessReceipt,
    ),
    String,
> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err(
            "remote policy lifecycle witness timeout must be between 1 and 600 seconds".into(),
        );
    }
    validate_policy_lifecycle_trust_state(state)?;
    validate_endpoint(endpoint, allow_http_loopback)?;
    let request = RemotePolicyLifecycleWitnessRequest {
        schema_version: 1,
        protocol: PROTOCOL,
        trust_state: state,
    };
    let request_bytes = serde_json::to_vec(&request)
        .map_err(|error| format!("serializing remote policy lifecycle witness request: {error}"))?;
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
            format!("remote policy lifecycle witness bearer-token environment {variable} is unset")
        })?;
        if token.trim().is_empty() {
            return Err(format!(
                "remote policy lifecycle witness bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call.send(request_bytes.clone()).map_err(|error| {
        format!("remote policy lifecycle witness HTTPS request failed: {error}")
    })?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "remote policy lifecycle witness returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err(
            "remote policy lifecycle witness response Content-Type must be application/json".into(),
        );
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| {
            format!("reading bounded remote policy lifecycle witness response: {error}")
        })?;
    if response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "remote policy lifecycle witness response exceeds {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let witness: SignedPolicyLifecycleCheckpointWitness = serde_json::from_slice(&response_bytes)
        .map_err(|error| {
        format!("invalid remote policy lifecycle witness response JSON: {error}")
    })?;
    verify_policy_lifecycle_checkpoint_witness(
        state,
        &witness,
        trusted_public_key,
        evaluated_at_unix,
    )?;
    let receipt = RemotePolicyLifecycleWitnessReceipt {
        schema_version: 1,
        adapter: "remote-policy-lifecycle-witness-https-v1".into(),
        endpoint: endpoint.into(),
        checkpoint_sha256: state.checkpoint_sha256.clone(),
        request_sha256,
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        evaluated_at_unix,
        witness_id: witness.witness_id.clone(),
        witness_public_key: witness.public_key.clone(),
        observed_at_unix: witness.observed_at_unix,
        verified: true,
    };
    Ok((witness, receipt))
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint
        .parse()
        .map_err(|error| format!("invalid remote policy lifecycle witness endpoint: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "remote policy lifecycle witness endpoint must have a scheme".to_string())?;
    if uri.authority().is_none() {
        return Err("remote policy lifecycle witness endpoint must have an authority".into());
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err("remote policy lifecycle witness endpoint must not contain userinfo".into());
    }
    if uri.query().is_some() {
        return Err("remote policy lifecycle witness endpoint must not contain a query".into());
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
        Err("remote policy lifecycle witness endpoint must use HTTPS".into())
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

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_receipts_and_rejects_unsafe_transport_configuration() {
        assert_eq!(
            remote_policy_lifecycle_witness_receipt_json_schema()["additionalProperties"],
            false
        );
        assert!(validate_endpoint("https://witness.example/v1/lifecycle", false).is_ok());
        assert!(
            validate_endpoint("https://witness.example/v1/lifecycle?token=secret", false).is_err()
        );
        assert!(validate_endpoint("https://secret@witness.example/v1/lifecycle", false).is_err());
        assert!(validate_endpoint("http://example.com/v1/lifecycle", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/lifecycle", false).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/lifecycle", true).is_ok());
        assert!(validate_env_name("PCBEX_LIFECYCLE_WITNESS_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
    }
}
