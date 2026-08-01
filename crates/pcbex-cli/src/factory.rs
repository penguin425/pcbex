//! Bounded factory quote and DFM-feedback adapters.
//!
//! Provider APIs change independently of pcbex.  The adapter therefore sends a
//! documented raw manufacturing ZIP over HTTPS and normalizes the JSON response
//! into a stable receipt.  Provider-specific authentication and endpoint paths
//! remain configuration, never source-code secrets.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{env, fs, path::Path, time::Duration};

const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FactoryProvider {
    Jlcpcb,
    Pcbway,
    Generic,
}

impl FactoryProvider {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "jlcpcb" | "jlc" => Ok(Self::Jlcpcb),
            "pcbway" => Ok(Self::Pcbway),
            "generic" => Ok(Self::Generic),
            _ => Err("factory provider must be one of: jlcpcb, pcbway, generic".into()),
        }
    }

    fn adapter_name(self) -> &'static str {
        match self {
            Self::Jlcpcb => "jlcpcb-http-v1",
            Self::Pcbway => "pcbway-http-v1",
            Self::Generic => "generic-factory-http-v1",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactoryDfmFinding {
    pub code: Option<String>,
    pub severity: String,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactorySubmissionReceipt {
    pub schema_version: u32,
    pub adapter: String,
    pub provider: FactoryProvider,
    pub endpoint: String,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub request_sha256: String,
    pub response_sha256: String,
    pub response_bytes: u64,
    pub http_status: u16,
    pub status: String,
    pub accepted: bool,
    pub dfm_passed: Option<bool>,
    pub quote: Option<Value>,
    pub findings: Vec<FactoryDfmFinding>,
    pub response: Value,
}

pub fn factory_submission_json_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-submission-receipt-v1.json",
        "title": "pcbex factory quote and DFM submission receipt",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "adapter", "provider", "endpoint", "package_sha256",
            "package_bytes", "request_sha256", "response_sha256", "response_bytes",
            "http_status", "status", "accepted", "dfm_passed", "quote", "findings", "response"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "adapter": {"type": "string", "pattern": "^[a-z0-9-]+$"},
            "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
            "endpoint": {"type": "string", "pattern": "^https://"},
            "package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "package_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "http_status": {"type": "integer", "minimum": 200, "maximum": 599},
            "status": {"type": "string"},
            "accepted": {"type": "boolean"},
            "dfm_passed": {"type": ["boolean", "null"]},
            "quote": {"type": ["object", "null"]},
            "findings": {"type": "array", "items": {"type": "object"}},
            "response": {"type": "object"}
        }
    })
}

/// Submit a manufacturing ZIP and normalize the provider's JSON response.
pub fn submit_factory_package(
    package_path: &Path,
    endpoint: &str,
    provider: FactoryProvider,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    allow_http_loopback: bool,
) -> Result<FactorySubmissionReceipt, String> {
    if !(1..=600).contains(&timeout_seconds) {
        return Err("factory timeout must be between 1 and 600 seconds".into());
    }
    validate_endpoint(endpoint, allow_http_loopback)?;
    let metadata = fs::metadata(package_path)
        .map_err(|error| format!("reading factory package metadata: {error}"))?;
    if !metadata.is_file() {
        return Err("factory package path must be a regular file".into());
    }
    if metadata.len() == 0 || metadata.len() > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }
    let package = fs::read(package_path).map_err(|error| {
        format!(
            "reading factory package {}: {error}",
            package_path.display()
        )
    })?;
    let package_sha256 = sha256(&package);
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_seconds)))
        .max_redirects(0)
        .build();
    let agent: ureq::Agent = config.into();
    let mut call = agent
        .post(endpoint)
        .header("Accept", "application/json")
        .header("Content-Type", "application/zip")
        .header("User-Agent", concat!("pcbex/", env!("CARGO_PKG_VERSION")))
        .header("X-PCBEX-Adapter", provider.adapter_name())
        .header("X-PCBEX-Schema-Version", "1")
        .header("X-PCBEX-Package-SHA256", &package_sha256);
    if let Some(variable) = bearer_token_env {
        validate_env_name(variable)?;
        let token = env::var(variable)
            .map_err(|_| format!("factory bearer-token environment {variable} is unset"))?;
        if token.trim().is_empty() {
            return Err(format!(
                "factory bearer-token environment {variable} is empty"
            ));
        }
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .send(package.clone())
        .map_err(|error| format!("factory HTTP request failed: {error}"))?;
    let http_status = response.status().as_u16();
    if !matches!(http_status, 200..=299) {
        return Err(format!(
            "factory returned unexpected HTTP status {http_status}"
        ));
    }
    if response.body().mime_type() != Some("application/json") {
        return Err("factory response Content-Type must be application/json".into());
    }
    let response_bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES + 1)
        .read_to_vec()
        .map_err(|error| format!("reading bounded factory response: {error}"))?;
    if response_bytes.is_empty() || response_bytes.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(format!(
            "factory response must contain 1 to {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    let response_source = std::str::from_utf8(&response_bytes)
        .map_err(|error| format!("factory response is not UTF-8: {error}"))?;
    let response_value: Value = serde_json::from_str(response_source)
        .map_err(|error| format!("factory response is not a JSON object: {error}"))?;
    if !response_value.is_object() {
        return Err("factory response JSON must be an object".into());
    }
    let normalized = normalize_response(&response_value)?;
    Ok(FactorySubmissionReceipt {
        schema_version: 1,
        adapter: provider.adapter_name().into(),
        provider,
        endpoint: endpoint.into(),
        package_sha256: package_sha256.clone(),
        package_bytes: package.len() as u64,
        request_sha256: package_sha256,
        response_sha256: sha256(&response_bytes),
        response_bytes: response_bytes.len() as u64,
        http_status,
        status: normalized.status,
        accepted: normalized.accepted,
        dfm_passed: normalized.dfm_passed,
        quote: normalized.quote,
        findings: normalized.findings,
        response: response_value,
    })
}

struct NormalizedResponse {
    status: String,
    accepted: bool,
    dfm_passed: Option<bool>,
    quote: Option<Value>,
    findings: Vec<FactoryDfmFinding>,
}

fn normalize_response(value: &Value) -> Result<NormalizedResponse, String> {
    let object = value
        .as_object()
        .expect("response object was validated before normalization");
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .trim()
        .to_string();
    let accepted = object
        .get("accepted")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            matches!(
                status.to_ascii_lowercase().as_str(),
                "accepted" | "quoted" | "success" | "ok" | "pass" | "passed"
            )
        });
    let dfm_passed = object
        .get("dfm_passed")
        .and_then(Value::as_bool)
        .or_else(|| {
            object
                .get("dfm")
                .and_then(|value| value.get("passed"))
                .and_then(Value::as_bool)
        });
    let quote = object.get("quote").cloned();
    let findings_value = object
        .get("dfm_findings")
        .or_else(|| object.get("findings"));
    let mut findings = Vec::new();
    if let Some(values) = findings_value {
        let values = values
            .as_array()
            .ok_or_else(|| "factory findings must be an array".to_string())?;
        for finding in values {
            let finding = finding
                .as_object()
                .ok_or_else(|| "factory finding must be an object".to_string())?;
            let message = finding
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("factory DFM finding")
                .to_string();
            findings.push(FactoryDfmFinding {
                code: finding
                    .get("code")
                    .or_else(|| finding.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                severity: finding
                    .get("severity")
                    .and_then(Value::as_str)
                    .unwrap_or("warning")
                    .to_ascii_lowercase(),
                message,
            });
        }
    }
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.code.cmp(&right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
    Ok(NormalizedResponse {
        status,
        accepted,
        dfm_passed,
        quote,
        findings,
    })
}

pub fn factory_feedback_passed(receipt: &FactorySubmissionReceipt) -> bool {
    receipt.dfm_passed == Some(true)
        && !receipt
            .findings
            .iter()
            .any(|finding| matches!(finding.severity.as_str(), "error" | "critical" | "fatal"))
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    let uri: ureq::http::Uri = endpoint
        .parse()
        .map_err(|error| format!("invalid factory endpoint: {error}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| "factory endpoint must have a scheme".to_string())?;
    if uri.authority().is_none() {
        return Err("factory endpoint must have an authority".into());
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err("factory endpoint must not contain userinfo".into());
    }
    if uri.query().is_some() {
        return Err("factory endpoint must not contain a query".into());
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
        Err("factory endpoint must use HTTPS".into())
    }
}

fn validate_env_name(value: &str) -> Result<(), String> {
    let mut bytes = value.bytes();
    let first = bytes.next();
    if !matches!(first, Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err("factory bearer-token environment name is invalid".into());
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
    fn normalizes_provider_feedback_and_gate() {
        let value = json!({
            "status": "quoted",
            "dfm": {"passed": false},
            "quote": {"total": 12.5, "currency": "USD"},
            "dfm_findings": [
                {"id": "clearance", "severity": "ERROR", "message": "too close"},
                {"code": "silk", "severity": "warning", "message": "overlap"}
            ]
        });
        let normalized = normalize_response(&value).unwrap();
        assert!(normalized.accepted);
        assert_eq!(normalized.dfm_passed, Some(false));
        assert_eq!(normalized.findings[0].severity, "error");
        let receipt = FactorySubmissionReceipt {
            schema_version: 1,
            adapter: "generic-factory-http-v1".into(),
            provider: FactoryProvider::Generic,
            endpoint: "https://factory.example/quote".into(),
            package_sha256: "a".repeat(64),
            package_bytes: 1,
            request_sha256: "a".repeat(64),
            response_sha256: "b".repeat(64),
            response_bytes: 1,
            http_status: 200,
            status: normalized.status,
            accepted: normalized.accepted,
            dfm_passed: normalized.dfm_passed,
            quote: normalized.quote,
            findings: normalized.findings,
            response: value,
        };
        assert!(!factory_feedback_passed(&receipt));
    }

    #[test]
    fn rejects_unsafe_endpoints_and_provider_names() {
        assert!(validate_endpoint("https://factory.example/quote", false).is_ok());
        assert!(validate_endpoint("https://factory.example/quote?token=secret", false).is_err());
        assert!(validate_endpoint("http://factory.example/quote", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:8080/quote", true).is_ok());
        assert_eq!(
            FactoryProvider::parse("jlc").unwrap(),
            FactoryProvider::Jlcpcb
        );
        assert!(FactoryProvider::parse("unknown").is_err());
    }
}
