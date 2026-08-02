//! Bounded factory quote and DFM-feedback adapters.
//!
//! Provider APIs change independently of pcbex.  The adapter therefore sends a
//! documented raw manufacturing ZIP over HTTPS and normalizes the JSON response
//! into a stable receipt.  Provider-specific authentication and endpoint paths
//! remain configuration, never source-code secrets.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    fs::File,
    io::{Cursor, Read},
    path::Path,
    time::Duration,
};
use zip::ZipArchive;

const MAX_PACKAGE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

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
            // HTTP is accepted only for an explicitly enabled local fixture;
            // production/provider endpoints remain HTTPS-only.  Keep the
            // schema able to describe those opt-in receipts as well.
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://[^/?#]+(?:/[^?#]*)?$"},
                    {"type": "string", "pattern": "^http://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?(?:/[^?#]*)?$"}
                ]
            },
            "package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "package_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "http_status": {"type": "integer", "minimum": 200, "maximum": 599},
            "status": {"type": "string", "minLength": 1},
            "accepted": {"type": "boolean"},
            "dfm_passed": {"type": ["boolean", "null"]},
            "quote": {"type": ["object", "null"]},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["code", "severity", "message"],
                    "properties": {
                        "code": {"type": ["string", "null"]},
                        "severity": {"type": "string", "minLength": 1},
                        "message": {"type": "string", "minLength": 1}
                    }
                }
            },
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
    // Open once and inspect/read that same handle.  A separate metadata/read
    // sequence could hash one file and upload another if the path is replaced
    // concurrently between the two operations.
    let package = read_package(package_path)?;
    validate_manufacturing_package(&package)?;
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
        validate_bearer_token(&token)?;
        call = call.header("Authorization", &format!("Bearer {token}"));
    }
    let mut response = call
        .send(package.as_slice())
        .map_err(|error| format!("factory HTTP request failed: {error}"))?;
    let http_status = response.status().as_u16();
    if !matches!(http_status, 200..=299) {
        return Err(format!(
            "factory returned unexpected HTTP status {http_status}"
        ));
    }
    if !response
        .body()
        .mime_type()
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("application/json"))
    {
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

#[derive(Debug, Deserialize)]
struct ManufacturingDescriptor {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
struct ManufacturingManifest {
    schema_version: u32,
    input: ManufacturingDescriptor,
    project_inputs: Vec<ManufacturingDescriptor>,
    artifacts: Vec<ManufacturingDescriptor>,
    archive: String,
}

fn read_package(package_path: &Path) -> Result<Vec<u8>, String> {
    let file = File::open(package_path).map_err(|error| {
        format!(
            "opening factory package {}: {error}",
            package_path.display()
        )
    })?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("reading factory package metadata: {error}"))?;
    if !metadata.is_file() {
        return Err("factory package path must be a regular file".into());
    }
    if metadata.len() > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }

    // The limit protects against a file growing after the metadata check while
    // still keeping the read bounded even when the initial size is stale.
    let mut package = Vec::new();
    file.take(MAX_PACKAGE_BYTES.saturating_add(1))
        .read_to_end(&mut package)
        .map_err(|error| format!("reading factory package: {error}"))?;
    if package.is_empty() || package.len() as u64 > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }
    Ok(package)
}

fn validate_manufacturing_package(package: &[u8]) -> Result<(), String> {
    let central_entries = central_directory_entry_count(package);
    if central_entries.is_some_and(|entries| entries > MAX_ARCHIVE_ENTRIES) {
        return Err(format!(
            "factory package contains more than {MAX_ARCHIVE_ENTRIES} ZIP entries"
        ));
    }
    let mut archive = ZipArchive::new(Cursor::new(package))
        .map_err(|error| format!("factory package is not a valid ZIP archive: {error}"))?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(format!(
            "factory package contains more than {MAX_ARCHIVE_ENTRIES} ZIP entries"
        ));
    }
    if let Some(central_entries) = central_entries
        && central_entries != archive.len()
    {
        return Err("factory package contains duplicate ZIP entry names".into());
    }
    let manifest = archive
        .by_name("manifest.json")
        .map_err(|_| "factory package must contain manifest.json".to_string())?;
    if !manifest.is_file() {
        return Err("factory package manifest.json must be a regular file".into());
    }
    let mut manifest_bytes = Vec::new();
    manifest
        .take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut manifest_bytes)
        .map_err(|error| format!("reading factory package manifest.json: {error}"))?;
    if manifest_bytes.is_empty() || manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "factory package manifest.json must contain 1 to {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    let manifest: ManufacturingManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("factory package manifest.json is not valid JSON: {error}"))?;
    if manifest.schema_version != 1 {
        return Err("factory package manifest.json must use schema_version 1".into());
    }
    if manifest.archive != "manufacturing.zip" {
        return Err(
            "factory package manifest.json must name manufacturing.zip as its archive".into(),
        );
    }

    validate_manifest_descriptor(&manifest.input, "input")?;
    let mut provenance_paths = BTreeSet::from([manifest.input.path.clone()]);
    for descriptor in &manifest.project_inputs {
        validate_manifest_descriptor(descriptor, "project input")?;
        if !provenance_paths.insert(descriptor.path.clone()) {
            return Err(format!(
                "factory package has duplicate provenance descriptor {}",
                descriptor.path
            ));
        }
    }
    if manifest.artifacts.is_empty() {
        return Err("factory package manifest.json must list at least one artifact".into());
    }
    let mut expected = BTreeMap::new();
    for descriptor in manifest.artifacts {
        validate_manifest_descriptor(&descriptor, "artifact")?;
        if descriptor.path == "manifest.json" || descriptor.path == "manufacturing.zip" {
            return Err(
                "factory package artifacts must not include manifest.json or manufacturing.zip"
                    .into(),
            );
        }
        if expected
            .insert(
                descriptor.path.clone(),
                (descriptor.bytes, descriptor.sha256),
            )
            .is_some()
        {
            return Err(format!(
                "factory package has duplicate manifest descriptor {}",
                descriptor.path
            ));
        }
    }
    let mut declared_uncompressed = 0_u64;
    for (name, (bytes, _)) in &expected {
        add_archive_size(&mut declared_uncompressed, *bytes, name)?;
    }

    let mut seen = BTreeSet::new();
    let mut total_uncompressed = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("reading factory package ZIP entry {index}: {error}"))?;
        let name = entry.name().to_string();
        if !is_safe_manifest_path(&name) {
            return Err(format!(
                "factory package contains unsafe ZIP entry path {name:?}"
            ));
        }
        if !seen.insert(name.clone()) {
            return Err(format!(
                "factory package contains duplicate ZIP entry {name}"
            ));
        }
        if !entry.is_file() {
            return Err(format!(
                "factory package ZIP entry {name} must be a regular file"
            ));
        }
        if name == "manifest.json" {
            continue;
        }
        let (expected_bytes, expected_hash) = expected
            .get(&name)
            .ok_or_else(|| format!("factory package contains unlisted ZIP entry {name}"))?;
        add_archive_size(&mut total_uncompressed, entry.size(), &name)?;
        let (actual_bytes, actual_hash) = hash_zip_entry(&mut entry, &name)?;
        if actual_bytes != *expected_bytes || actual_hash != *expected_hash {
            return Err(format!(
                "factory package ZIP entry {name} does not match manifest bytes/hash"
            ));
        }
    }
    if seen.len() != expected.len() + 1 {
        let missing = expected
            .keys()
            .find(|name| !seen.contains(*name))
            .cloned()
            .unwrap_or_else(|| "unknown".into());
        return Err(format!(
            "factory package is missing manifest entry {missing}"
        ));
    }
    Ok(())
}

fn add_archive_size(total: &mut u64, size: u64, name: &str) -> Result<(), String> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| format!("factory package ZIP entry {name} size overflow"))?;
    if *total > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
        return Err(format!(
            "factory package decompressed artifact bytes exceed {MAX_ARCHIVE_UNCOMPRESSED_BYTES}"
        ));
    }
    Ok(())
}

fn central_directory_entry_count(package: &[u8]) -> Option<usize> {
    const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
    const EOCD_LENGTH: usize = 22;
    let search_start = package
        .len()
        .saturating_sub(EOCD_LENGTH + u16::MAX as usize);
    let search_end = package.len().checked_sub(EOCD_LENGTH)?;
    for offset in (search_start..=search_end).rev() {
        if package.get(offset..offset + 4)? != EOCD_SIGNATURE {
            continue;
        }
        let entries = u16::from_le_bytes(package.get(offset + 10..offset + 12)?.try_into().ok()?);
        if entries == u16::MAX {
            // ZIP64 central-directory counts need a separate locator parse;
            // ZipArchive already bounds the entry table in this case.
            return None;
        }
        let central_size =
            u32::from_le_bytes(package.get(offset + 12..offset + 16)?.try_into().ok()?) as usize;
        let central_offset =
            u32::from_le_bytes(package.get(offset + 16..offset + 20)?.try_into().ok()?) as usize;
        if central_offset.checked_add(central_size)? > offset {
            continue;
        }
        return Some(entries as usize);
    }
    None
}

fn validate_manifest_descriptor(
    descriptor: &ManufacturingDescriptor,
    kind: &str,
) -> Result<(), String> {
    if !is_safe_manifest_path(&descriptor.path) {
        return Err(format!(
            "factory package {kind} descriptor has unsafe path {:?}",
            descriptor.path
        ));
    }
    if descriptor.path == "manufacturing.zip" {
        return Err(format!(
            "factory package {kind} descriptor must not reference manufacturing.zip"
        ));
    }
    if descriptor.bytes > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory package {kind} descriptor has invalid byte count"
        ));
    }
    if !is_sha256(&descriptor.sha256) {
        return Err(format!(
            "factory package {kind} descriptor has invalid SHA-256"
        ));
    }
    Ok(())
}

fn is_safe_manifest_path(path: &str) -> bool {
    !path.is_empty()
        && path != "."
        && path != ".."
        && !path.contains('/')
        && !path.contains('\\')
        && !path.contains('\0')
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hash_zip_entry<R: Read>(
    entry: &mut zip::read::ZipFile<'_, R>,
    name: &str,
) -> Result<(u64, String), String> {
    if entry.size() > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory package ZIP entry {name} exceeds size limit"
        ));
    }
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = entry
            .read(&mut buffer)
            .map_err(|error| format!("reading factory package ZIP entry {name}: {error}"))?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| format!("factory package ZIP entry {name} size overflow"))?;
        if bytes > MAX_PACKAGE_BYTES {
            return Err(format!(
                "factory package ZIP entry {name} exceeds size limit"
            ));
        }
        digest.update(&buffer[..read]);
    }
    Ok((bytes, hex::encode(digest.finalize())))
}

fn normalize_response(value: &Value) -> Result<NormalizedResponse, String> {
    let object = value
        .as_object()
        .expect("response object was validated before normalization");
    if object.contains_key("dfm_passed") && object.contains_key("dfm") {
        return Err("factory response must not contain both dfm_passed and dfm".into());
    }
    if object.contains_key("dfm_findings") && object.contains_key("findings") {
        return Err("factory response must not contain both dfm_findings and findings".into());
    }
    let status = match object.get("status") {
        Some(value) => {
            let status = value
                .as_str()
                .ok_or_else(|| "factory status must be a string".to_string())?
                .trim();
            if status.is_empty() {
                return Err("factory status must not be blank".into());
            }
            status.to_string()
        }
        None => "unknown".to_string(),
    };
    let accepted = match object.get("accepted") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "factory accepted must be a boolean".to_string())?,
        None => matches!(
            status.to_ascii_lowercase().as_str(),
            "accepted" | "quoted" | "success" | "ok" | "pass" | "passed"
        ),
    };
    let dfm_passed = match object.get("dfm_passed") {
        Some(value) if value.is_null() => None,
        Some(value) => Some(
            value
                .as_bool()
                .ok_or_else(|| "factory dfm_passed must be a boolean or null".to_string())?,
        ),
        None => match object.get("dfm") {
            None => None,
            Some(value) => {
                let dfm = value
                    .as_object()
                    .ok_or_else(|| "factory dfm must be an object".to_string())?;
                match dfm.get("passed") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(value.as_bool().ok_or_else(|| {
                        "factory dfm.passed must be a boolean or null".to_string()
                    })?),
                }
            }
        },
    };
    let quote = object.get("quote").cloned();
    if quote
        .as_ref()
        .is_some_and(|value| !value.is_object() && !value.is_null())
    {
        return Err("factory quote must be an object or null".into());
    }
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
            let message = match finding.get("message") {
                Some(value) => {
                    let message = value
                        .as_str()
                        .ok_or_else(|| "factory finding message must be a string".to_string())?
                        .trim();
                    if message.is_empty() {
                        return Err("factory finding message must not be blank".into());
                    }
                    message.to_string()
                }
                None => "factory DFM finding".to_string(),
            };
            if finding.contains_key("code") && finding.contains_key("id") {
                return Err("factory finding must not contain both code and id".into());
            }
            let code = match finding.get("code").or_else(|| finding.get("id")) {
                None | Some(Value::Null) => None,
                Some(value) => {
                    let code = value
                        .as_str()
                        .ok_or_else(|| "factory finding code must be a string or null".to_string())?
                        .trim();
                    (!code.is_empty()).then(|| code.to_string())
                }
            };
            let severity = match finding.get("severity") {
                Some(value) => {
                    let severity = value
                        .as_str()
                        .ok_or_else(|| "factory finding severity must be a string".to_string())?
                        .trim()
                        .to_ascii_lowercase();
                    if severity.is_empty() {
                        "unknown".to_string()
                    } else {
                        severity
                    }
                }
                None => "unknown".to_string(),
            };
            findings.push(FactoryDfmFinding {
                code,
                severity,
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
    (200..=299).contains(&receipt.http_status)
        && receipt.accepted
        && receipt.dfm_passed == Some(true)
        && !receipt.findings.iter().any(|finding| {
            matches!(finding.severity.as_str(), "error" | "critical" | "fatal")
                || !matches!(finding.severity.as_str(), "info" | "notice" | "warning")
        })
}

fn validate_endpoint(endpoint: &str, allow_http_loopback: bool) -> Result<(), String> {
    // `http::Uri` deliberately discards URI fragments. Reject them before
    // parsing so the transported endpoint and the audited receipt stay equal.
    if endpoint.contains('#') {
        return Err("factory endpoint must not contain a fragment".into());
    }
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
    let host = uri.host().unwrap_or_default();
    if host.is_empty() {
        return Err("factory endpoint must have a host".into());
    }
    if scheme == "https" {
        return Ok(());
    }
    let loopback = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
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

fn validate_bearer_token(value: &str) -> Result<(), String> {
    // RFC 6750 tokens are ASCII.  Accept the broader visible-ASCII range so
    // providers using opaque tokens with punctuation remain compatible, while
    // rejecting whitespace, controls, and Unicode that cannot be represented
    // safely in an HTTP header.
    if value.is_empty()
        || value.trim() != value
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err("factory bearer-token environment contains invalid characters".into());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        io::Write,
        net::{TcpListener, TcpStream},
        sync::{Arc, Mutex},
        thread::{self, JoinHandle},
    };
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    fn manufacturing_package() -> Vec<u8> {
        let board = b"board-bytes";
        let artifact = b"gerber-bytes";
        let manifest = json!({
            "schema_version": 1,
            "engine": "pcbex",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "tools": {"kicad_cli": "10.0.5", "kicad_cli_about_sha256": "about"},
            "input": {
                "path": "board.kicad_pcb",
                "bytes": board.len(),
                "sha256": sha256(board)
            },
            "project_inputs": [],
            "parts": {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
            "artifacts": [{
                "path": "board-F_Cu.gbr",
                "bytes": artifact.len(),
                "sha256": sha256(artifact)
            }],
            "archive": "manufacturing.zip"
        });
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("board-F_Cu.gbr", options).unwrap();
        writer.write_all(artifact).unwrap();
        writer.start_file("manifest.json", options).unwrap();
        writer.write_all(&manifest_bytes).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn spawn_http_fixture(
        status: u16,
        content_type: &str,
        body: Vec<u8>,
        extra_headers: &[&str],
    ) -> (String, Arc<Mutex<Vec<u8>>>, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let endpoint = format!("http://{}/quote", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_by_server = Arc::clone(&received);
        let content_type = content_type.to_string();
        let extra_headers = extra_headers.join("\r\n");
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            *received_by_server.lock().unwrap() = request;
            let mut response = format!(
                "HTTP/1.1 {status} OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if !extra_headers.is_empty() {
                response.push_str(&extra_headers);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
        });
        (endpoint, received, handle)
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 8192];
        let header_end = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert!(read > 0, "factory client closed before sending headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break index;
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
        let request_length = header_end + 4 + content_length;
        while request.len() < request_length {
            let read = stream.read(&mut buffer).unwrap();
            assert!(
                read > 0,
                "factory client closed before sending request body"
            );
            request.extend_from_slice(&buffer[..read]);
        }
        request.truncate(request_length);
        request
    }

    fn write_package(path: &Path) -> Vec<u8> {
        let package = manufacturing_package();
        fs::write(path, &package).unwrap();
        package
    }

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

        let mut passing = receipt;
        passing.dfm_passed = Some(true);
        passing.accepted = false;
        assert!(!factory_feedback_passed(&passing));
        passing.accepted = true;
        passing.findings.clear();
        assert!(factory_feedback_passed(&passing));
        passing.findings.push(FactoryDfmFinding {
            code: None,
            severity: "vendor-specific".into(),
            message: "unknown severity must fail closed".into(),
        });
        assert!(!factory_feedback_passed(&passing));

        assert!(normalize_response(&json!({"status": 7})).is_err());
        assert!(normalize_response(&json!({"status": "   "})).is_err());
        assert!(normalize_response(&json!({"accepted": "yes"})).is_err());
        assert!(
            normalize_response(&json!({
                "dfm_passed": true,
                "dfm": {"passed": true}
            }))
            .is_err()
        );
        assert!(
            normalize_response(&json!({
                "dfm_findings": [],
                "findings": []
            }))
            .is_err()
        );
        assert!(
            normalize_response(&json!({
                "findings": [{"code": "a", "id": "b"}]
            }))
            .is_err()
        );
        let missing_severity = normalize_response(&json!({
            "findings": [{"message": "missing severity must fail closed"}]
        }))
        .unwrap();
        assert_eq!(missing_severity.findings[0].severity, "unknown");
        assert!(normalize_response(&json!({"findings": [{"message": "   "}]})).is_err());
        let blank_code_and_severity = normalize_response(&json!({
            "findings": [{"code": " ", "severity": " "}]
        }))
        .unwrap();
        assert_eq!(blank_code_and_severity.findings[0].code, None);
        assert_eq!(blank_code_and_severity.findings[0].severity, "unknown");
    }

    #[test]
    fn rejects_unsafe_endpoints_and_provider_names() {
        assert!(validate_endpoint("https://factory.example/quote", false).is_ok());
        assert!(validate_endpoint("https://factory.example/quote?token=secret", false).is_err());
        assert!(validate_endpoint("https://factory.example/quote#fragment", false).is_err());
        assert!(validate_endpoint("http://factory.example/quote", true).is_err());
        assert!(validate_endpoint("http://127.0.0.1:8080/quote", true).is_ok());
        assert!(validate_endpoint("http://127.0.0.2:8080/quote", true).is_err());
        assert!(validate_endpoint("https:///quote", false).is_err());
        assert!(validate_bearer_token("token-value").is_ok());
        assert!(validate_bearer_token(" token-value").is_err());
        assert!(validate_bearer_token("token\nvalue").is_err());
        assert!(validate_bearer_token("トークン").is_err());
        assert_eq!(
            FactoryProvider::parse("jlc").unwrap(),
            FactoryProvider::Jlcpcb
        );
        assert!(FactoryProvider::parse("unknown").is_err());
    }

    #[test]
    fn caps_total_uncompressed_archive_entries() {
        let mut total = MAX_ARCHIVE_UNCOMPRESSED_BYTES - 1;
        assert!(add_archive_size(&mut total, 2, "large.gbr").is_err());
        let mut total = u64::MAX;
        assert!(add_archive_size(&mut total, 1, "overflow.gbr").is_err());

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("duplicate.txt", options).unwrap();
        writer.write_all(b"one").unwrap();
        let _ = writer.finish().unwrap().into_inner();
    }

    #[test]
    fn accepts_archive_emitted_by_manufacturing_package_writer() {
        let staging = tempdir().unwrap();
        fs::write(staging.path().join("drc.rpt"), "DRC clean\n").unwrap();
        fs::write(staging.path().join("board-F_Cu.gtl"), "G04 copper*\n").unwrap();
        let archive = crate::manufacturing_package::write_manufacturing_package(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[crate::manufacturing_package::KiCadProjectInput {
                path: Path::new("board.kicad_pro").to_path_buf(),
                bytes: Vec::new(),
            }],
            &[],
            &[
                staging.path().join("drc.rpt"),
                staging.path().join("board-F_Cu.gtl"),
            ],
            &crate::manufacturing_package::KiCadIdentity {
                version: "10.0.5".into(),
                about_sha256: "about".into(),
            },
        )
        .unwrap();
        validate_manufacturing_package(&fs::read(archive).unwrap()).unwrap();
    }

    #[test]
    fn submits_valid_package_with_expected_request_and_deterministic_receipt() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let response_value = json!({
            "status": "  Quoted ",
            "dfm_passed": true,
            "quote": {"total": 12.5, "currency": "USD"},
            "dfm_findings": [
                {"code": "silk", "severity": " WARNING ", "message": "overlap"},
                {"code": "clearance", "severity": "INFO", "message": "checked"}
            ]
        });
        let response_bytes = serde_json::to_vec(&response_value).unwrap();
        let (endpoint, received, handle) = spawn_http_fixture(
            200,
            "Application/JSON; charset=utf-8",
            response_bytes.clone(),
            &[],
        );
        let variable = format!("PCBEX_FACTORY_TEST_TOKEN_{}", std::process::id());
        unsafe { env::set_var(&variable, "token-value") };
        let receipt = submit_factory_package(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            Some(&variable),
            5,
            true,
        )
        .unwrap();
        unsafe { env::remove_var(&variable) };
        handle.join().unwrap();

        let request = received.lock().unwrap().clone();
        let request_text = String::from_utf8_lossy(&request).to_ascii_lowercase();
        assert!(request_text.starts_with("post /quote http/1.1\r\n"));
        assert!(request_text.contains("accept: application/json\r\n"));
        assert!(request_text.contains("content-type: application/zip\r\n"));
        assert!(request_text.contains("authorization: bearer token-value\r\n"));
        assert!(request_text.contains("x-pcbex-adapter: generic-factory-http-v1\r\n"));
        assert!(request_text.contains("x-pcbex-schema-version: 1\r\n"));
        assert!(
            request_text.contains(&format!("x-pcbex-package-sha256: {}\r\n", sha256(&package)))
        );
        let body_start = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        assert_eq!(&request[body_start..], package.as_slice());

        assert_eq!(receipt.schema_version, 1);
        assert_eq!(receipt.endpoint, endpoint);
        assert_eq!(receipt.package_bytes, package.len() as u64);
        assert_eq!(receipt.package_sha256, sha256(&package));
        assert_eq!(receipt.request_sha256, receipt.package_sha256);
        assert_eq!(receipt.response_bytes, response_bytes.len() as u64);
        assert_eq!(receipt.response_sha256, sha256(&response_bytes));
        assert_eq!(receipt.status, "Quoted");
        assert!(receipt.accepted);
        assert_eq!(receipt.dfm_passed, Some(true));
        assert_eq!(receipt.findings[0].severity, "info");
        assert_eq!(receipt.findings[1].severity, "warning");
        assert!(factory_feedback_passed(&receipt));
    }

    #[test]
    fn rejects_package_bounds_and_archive_integrity_errors_before_network() {
        let temporary = tempdir().unwrap();
        let endpoint = "https://factory.example/quote";
        let empty = temporary.path().join("empty.zip");
        fs::write(&empty, []).unwrap();
        assert!(
            submit_factory_package(&empty, endpoint, FactoryProvider::Generic, None, 5, false)
                .unwrap_err()
                .contains("1 to")
        );

        let oversized = temporary.path().join("oversized.zip");
        let file = fs::File::create(&oversized).unwrap();
        file.set_len(MAX_PACKAGE_BYTES + 1).unwrap();
        assert!(
            submit_factory_package(
                &oversized,
                endpoint,
                FactoryProvider::Generic,
                None,
                5,
                false
            )
            .unwrap_err()
            .contains("1 to")
        );

        let arbitrary = temporary.path().join("arbitrary.zip");
        fs::write(&arbitrary, b"not a zip").unwrap();
        assert!(
            submit_factory_package(
                &arbitrary,
                endpoint,
                FactoryProvider::Generic,
                None,
                5,
                false
            )
            .unwrap_err()
            .contains("valid ZIP")
        );

        let valid = temporary.path().join("valid.zip");
        let mut package = write_package(&valid);
        let index = package
            .windows(4)
            .position(|window| window == b"gerb")
            .unwrap();
        package[index] ^= 1;
        fs::write(&valid, &package).unwrap();
        let error =
            submit_factory_package(&valid, endpoint, FactoryProvider::Generic, None, 5, false)
                .unwrap_err();
        assert!(
            error.contains("does not match manifest") || error.contains("Invalid checksum"),
            "{error}"
        );
    }

    #[test]
    fn rejects_redirect_content_type_json_status_and_response_bounds() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        write_package(&package_path);
        let cases = [
            (
                302,
                "application/json",
                br#"{"status":"quoted"}"#.to_vec(),
                &["Location: https://factory.example/quote"][..],
                "HTTP",
            ),
            (
                200,
                "text/plain",
                br#"{"status":"quoted"}"#.to_vec(),
                &[][..],
                "Content-Type",
            ),
            (
                200,
                "application/json",
                b"not-json".to_vec(),
                &[][..],
                "not a JSON",
            ),
        ];
        for (status, content_type, body, headers, expected) in cases {
            let (endpoint, _received, handle) =
                spawn_http_fixture(status, content_type, body, headers);
            let error = submit_factory_package(
                &package_path,
                &endpoint,
                FactoryProvider::Generic,
                None,
                5,
                true,
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
            handle.join().unwrap();
        }

        let oversized_response = vec![b' '; (MAX_RESPONSE_BYTES + 1) as usize];
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", oversized_response, &[]);
        let error = submit_factory_package(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
        )
        .unwrap_err();
        assert!(error.contains("bounded factory response") || error.contains("1 to"));
        handle.join().unwrap();
    }
}
