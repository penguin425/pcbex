use crate::policy_pack::{
    OrganizationPolicyPack, PolicyTrustState, SignedPolicyPack, advance_policy_trust_state,
    parse_signed_policy_pack, verify_signed_policy_pack,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, time::Duration};

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemotePolicyPackReceipt {
    pub schema_version: u32,
    pub adapter: String,
    pub endpoint: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub policy_pack_id: String,
    pub policy_pack_revision: u32,
    pub policy_pack_sha256: String,
    pub signer_id: String,
    pub signer_public_key: String,
    pub baseline_revision: Option<u32>,
    pub baseline_sha256: Option<String>,
    pub verified: bool,
}

pub struct FetchedPolicyPack {
    pub signed: SignedPolicyPack,
    pub policy_pack: OrganizationPolicyPack,
    pub trust_state: PolicyTrustState,
    pub receipt: RemotePolicyPackReceipt,
}

pub fn remote_policy_pack_receipt_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/remote-policy-pack-receipt-v1.json",
        "title": "pcbex remote policy-pack retrieval receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "endpoint", "response_sha256",
            "response_bytes", "policy_pack_id", "policy_pack_revision",
            "policy_pack_sha256", "signer_id", "signer_public_key",
            "baseline_revision", "baseline_sha256", "verified"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"const": "central-policy-registry-http-v1"},
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://"},
                    {"type": "string", "pattern": "^http://(localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?/"}
                ]
            },
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {
                "type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES
            },
            "policy_pack_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
            "policy_pack_revision": {"type": "integer", "minimum": 1},
            "policy_pack_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "signer_id": {
                "type": "string", "pattern": "^[a-z0-9][a-z0-9.-]{0,127}$"
            },
            "signer_public_key": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "baseline_revision": {
                "type": ["integer", "null"], "minimum": 1
            },
            "baseline_sha256": {
                "anyOf": [
                    {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    {"type": "null"}
                ]
            },
            "verified": {"const": true}
        }
    })
}

pub fn fetch_remote_policy_pack(
    endpoint: &str,
    trusted_public_key: &[u8; 32],
    baseline: Option<&PolicyTrustState>,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    allow_http_loopback: bool,
) -> Result<FetchedPolicyPack, String> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err("policy registry timeout must be between 1 and 600 seconds".into());
    }
    validate_endpoint(endpoint, allow_http_loopback)?;
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .build();
    let agent: ureq::Agent = config.into();
    let mut call = agent
        .get(endpoint)
        .header("Accept", "application/json")
        .header("User-Agent", concat!("pcbex/", env!("CARGO_PKG_VERSION")));
    if let Some(variable) = bearer_token_env {
        validate_env_name(variable)?;
        let token = env::var(variable)
            .map_err(|_| format!("policy registry bearer-token environment {variable} is unset"))?;
        if token.trim().is_empty() {
            return Err(format!(
                "policy registry bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .call()
        .map_err(|error| format!("policy registry HTTP request failed: {error}"))?;
    if response.status().as_u16() != 200 {
        return Err(format!(
            "policy registry returned unexpected HTTP status {}",
            response.status()
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err("policy registry response Content-Type must be application/json".into());
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| format!("reading bounded policy registry response: {error}"))?;
    if response_bytes.is_empty() || response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "policy registry response must contain 1 to {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let source = std::str::from_utf8(&response_bytes)
        .map_err(|error| format!("policy registry response is not UTF-8: {error}"))?;
    let signed = parse_signed_policy_pack(source)?;
    verify_signed_policy_pack(&signed, trusted_public_key)?;
    let trust_state = advance_policy_trust_state(&signed, baseline)?;
    let receipt = RemotePolicyPackReceipt {
        schema_version: 1,
        adapter: "central-policy-registry-http-v1".into(),
        endpoint: endpoint.into(),
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        policy_pack_id: signed.policy_pack.id.clone(),
        policy_pack_revision: signed.policy_pack.revision,
        policy_pack_sha256: signed.policy_pack_sha256.clone(),
        signer_id: signed.signer_id.clone(),
        signer_public_key: signed.public_key.clone(),
        baseline_revision: baseline.map(|state| state.accepted_revision),
        baseline_sha256: baseline.map(|state| state.policy_pack_sha256.clone()),
        verified: true,
    };
    Ok(FetchedPolicyPack {
        policy_pack: signed.policy_pack.clone(),
        signed,
        trust_state,
        receipt,
    })
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint
        .parse()
        .map_err(|error| format!("invalid policy registry endpoint: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "policy registry endpoint must have a scheme".to_string())?;
    if uri.authority().is_none() {
        return Err("policy registry endpoint must have an authority".into());
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err("policy registry endpoint must not contain userinfo".into());
    }
    if uri.query().is_some() {
        return Err("policy registry endpoint must not contain a query".into());
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
        Err("policy registry endpoint must use HTTPS".into())
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
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closes_receipts_and_rejects_unsafe_transport_configuration() {
        assert_eq!(
            remote_policy_pack_receipt_json_schema()["additionalProperties"],
            false
        );
        assert!(validate_endpoint("https://policies.example/v1/current", false).is_ok());
        assert!(
            validate_endpoint("https://policies.example/v1/current?token=secret", false).is_err()
        );
        assert!(validate_endpoint("https://secret@policies.example/v1/current", false).is_err());
        assert!(validate_endpoint("http://example.com/v1/current", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/current", false).is_err());
        assert!(validate_endpoint("http://127.0.0.1:1234/v1/current", true).is_ok());
        assert!(validate_env_name("PCBEX_POLICY_TOKEN").is_ok());
        assert!(validate_env_name("BAD-NAME").is_err());
    }
}
