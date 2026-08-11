//! Bounded factory quote and DFM-feedback adapters.
//!
//! Provider APIs change independently of pcbex.  The adapter therefore sends a
//! documented raw manufacturing ZIP over HTTPS and normalizes the JSON response
//! into a stable receipt.  Provider-specific authentication and endpoint paths
//! remain configuration, never source-code secrets.

use crate::bounded_process::{ProcessError, ProcessLimits, run_bounded_with_stdin_file};
use crate::deterministic_pipeline_runner::reject_duplicate_json_keys;
use crate::dfm_profile_binding::{DfmProfileBinding, validate_dfm_profile_binding};
use crate::manufacturing_limits::{
    MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_UNCOMPRESSED_BYTES, MAX_MANIFEST_BYTES, MAX_PACKAGE_BYTES,
    ManufacturingLimits, portable_manufacturing_name_key, scan_manufacturing_workspace,
    validate_manufacturing_basename,
};
use crate::physical_profile::{PhysicalProfileBinding, validate_physical_profile_binding};
use flate2::{Decompress, FlushDecompress, Status};
use pcbex_kicad::MAX_MANUFACTURING_PARTS;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};
use tempfile::{Builder as TempfileBuilder, NamedTempFile};
use zip::ZipArchive;

const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_REPAIR_ATTEMPTS: u8 = 4;
const FACTORY_LOOP_TIMEOUT_SECONDS: u64 = 900;
const REPAIR_TIMEOUT_SECONDS: u64 = 600;
const MAX_LOOP_ERROR_CHARS: usize = 4096;
const MAX_FACTORY_FINDINGS: usize = 100_000;
const MAX_FACTORY_ADAPTER_CHARS: usize = 64;
const MAX_FACTORY_ENDPOINT_CHARS: usize = 2048;
const MAX_FACTORY_STATUS_CHARS: usize = 4096;
const MAX_FACTORY_SEVERITY_CHARS: usize = 64;
const MAX_FACTORY_FINDING_CODE_CHARS: usize = 256;
const MAX_FACTORY_FINDING_MESSAGE_CHARS: usize = 4096;
const FACTORY_REPAIR_PROCESS_STDOUT_LIMIT_BYTES: usize = 1024 * 1024;
const FACTORY_REPAIR_PROCESS_STDERR_LIMIT_BYTES: usize = 1024 * 1024;
// Keep the parser bound aligned with the existing per-entry quota.  In
// particular, one grouped BOM row may legitimately contain many designators
// and can therefore be larger than a conventional line-size limit.
const MAX_CSV_RECORD_BYTES: usize = MAX_PACKAGE_BYTES as usize;

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

#[derive(Clone, Debug, Serialize)]
pub struct FactoryLoopAttempt {
    pub attempt: u8,
    pub package_sha256: String,
    pub package_bytes: u64,
    pub receipt: Option<FactorySubmissionReceipt>,
    pub error: Option<String>,
    pub repair_command_ran: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct FactoryFeedbackLoopReport {
    pub schema_version: u32,
    pub passed: bool,
    pub attempts: Vec<FactoryLoopAttempt>,
    pub final_package_sha256: String,
    pub final_package_bytes: u64,
    pub failure: Option<String>,
}

/// The auditable loop report together with the last package that passed full
/// local manufacturing-package validation.  The package bytes are deliberately
/// not serialized into the JSON report.
#[derive(Debug)]
pub struct FactoryFeedbackLoopOutcome {
    pub report: FactoryFeedbackLoopReport,
    pub final_package: Vec<u8>,
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
            "adapter": {"type": "string", "pattern": "^[a-z0-9-]+$", "minLength": 1, "maxLength": MAX_FACTORY_ADAPTER_CHARS},
            "provider": {"enum": ["jlcpcb", "pcbway", "generic"]},
            // HTTP is accepted only for an explicitly enabled local fixture;
            // production/provider endpoints remain HTTPS-only.  Keep the
            // schema able to describe those opt-in receipts as well.
            "endpoint": {
                "anyOf": [
                    {"type": "string", "pattern": "^https://[^/?#@]+(?:/[^?#]*)?$", "maxLength": MAX_FACTORY_ENDPOINT_CHARS},
                    {"type": "string", "pattern": "^http://(?:localhost|127\\.0\\.0\\.1|\\[::1\\])(?::[0-9]+)?(?:/[^?#]*)?$", "maxLength": MAX_FACTORY_ENDPOINT_CHARS}
                ]
            },
            "package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "package_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
            "request_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "response_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_RESPONSE_BYTES},
            "http_status": {"type": "integer", "minimum": 200, "maximum": 599},
            "status": {"type": "string", "minLength": 1, "maxLength": MAX_FACTORY_STATUS_CHARS, "pattern": "^\\S(?:[\\s\\S]*\\S)?$"},
            "accepted": {"type": "boolean"},
            "dfm_passed": {"type": ["boolean", "null"]},
            "quote": {"type": ["object", "null"]},
            "findings": {
                "type": "array",
                "maxItems": MAX_FACTORY_FINDINGS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["code", "severity", "message"],
                    "properties": {
                        "code": {
                            "anyOf": [
                                {"type": "null"},
                                {"type": "string", "minLength": 1, "maxLength": MAX_FACTORY_FINDING_CODE_CHARS, "pattern": "^\\S(?:[\\s\\S]*\\S)?$"}
                            ]
                        },
                        "severity": {"type": "string", "minLength": 1, "maxLength": MAX_FACTORY_SEVERITY_CHARS, "pattern": "^[^A-Z\\s](?:[^A-Z]*[^A-Z\\s])?$"},
                        "message": {"type": "string", "minLength": 1, "maxLength": MAX_FACTORY_FINDING_MESSAGE_CHARS, "pattern": "^\\S(?:[\\s\\S]*\\S)?$"}
                    }
                }
            },
            "response": {"type": "object"}
        }
    })
}

pub fn factory_feedback_loop_json_schema() -> Value {
    let submission_schema = factory_submission_json_schema();
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schema/factory-feedback-loop-v1.json",
        "title": "pcbex bounded factory feedback loop report",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "passed", "attempts", "final_package_sha256", "final_package_bytes", "failure"],
        "properties": {
            "schema_version": {"const": 1},
            "passed": {"type": "boolean"},
            "attempts": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_REPAIR_ATTEMPTS,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "attempt", "package_sha256", "package_bytes", "receipt", "error",
                        "repair_command_ran"
                    ],
                    "properties": {
                        "attempt": {"type": "integer", "minimum": 1, "maximum": MAX_REPAIR_ATTEMPTS},
                        "package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "package_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
                        "receipt": {
                            "anyOf": [
                                {"$ref": "#/$defs/factory_submission_receipt"},
                                {"type": "null"}
                            ]
                        },
                        "error": {
                            "type": ["string", "null"],
                            "minLength": 1,
                            "maxLength": MAX_LOOP_ERROR_CHARS
                        },
                        "repair_command_ran": {"type": "boolean"}
                    },
                    "allOf": [{
                        "if": {
                            "required": ["receipt"],
                            "properties": {"receipt": {"type": "null"}}
                        },
                        "then": {
                            "properties": {
                                "error": {"type": "string", "minLength": 1, "maxLength": MAX_LOOP_ERROR_CHARS},
                                "repair_command_ran": {"const": false}
                            }
                        }
                    }]
                }
            },
            "final_package_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "final_package_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PACKAGE_BYTES},
            "failure": {
                "type": ["string", "null"],
                "minLength": 1,
                "maxLength": MAX_LOOP_ERROR_CHARS
            }
        },
        "allOf": [{
            "if": {
                "required": ["passed"],
                "properties": {"passed": {"const": true}}
            },
            "then": {"properties": {"failure": {"type": "null"}}},
            "else": {
                "properties": {
                    "failure": {"type": "string", "minLength": 1, "maxLength": MAX_LOOP_ERROR_CHARS}
                }
            }
        }],
        "$defs": {"factory_submission_receipt": submission_schema}
    })
}

/// Submit a package, then invoke a bounded shell-free repair command when DFM
/// fails. The repair command receives the current receipt on stdin and the
/// package paths through `PCBEX_FACTORY_REPAIR_*` environment variables; it
/// must write the next ZIP to the declared output path.
#[allow(clippy::too_many_arguments)]
pub fn run_factory_feedback_loop(
    package_path: &Path,
    endpoint: &str,
    provider: FactoryProvider,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    max_attempts: u8,
    repair_command: Option<&Path>,
) -> Result<FactoryFeedbackLoopOutcome, String> {
    run_factory_feedback_loop_with_limits(
        package_path,
        endpoint,
        provider,
        bearer_token_env,
        timeout_seconds,
        allow_http_loopback,
        max_attempts,
        repair_command,
        FactoryLoopLimits::production(),
    )
}

#[derive(Clone, Copy)]
struct FactoryLoopLimits {
    total: Duration,
    repair: Duration,
    manufacturing: ManufacturingLimits,
}

impl FactoryLoopLimits {
    const fn production() -> Self {
        Self {
            total: Duration::from_secs(FACTORY_LOOP_TIMEOUT_SECONDS),
            repair: Duration::from_secs(REPAIR_TIMEOUT_SECONDS),
            manufacturing: ManufacturingLimits::production(),
        }
    }
}

struct PackageSnapshot {
    file: NamedTempFile,
    bytes: Vec<u8>,
}

impl PackageSnapshot {
    fn path(&self) -> &Path {
        self.file.path()
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

struct RepairCommandOutcome {
    command_ran: bool,
    result: Result<Vec<u8>, String>,
}

#[allow(clippy::too_many_arguments)]
fn run_factory_feedback_loop_with_limits(
    package_path: &Path,
    endpoint: &str,
    provider: FactoryProvider,
    bearer_token_env: Option<&str>,
    timeout_seconds: u64,
    allow_http_loopback: bool,
    max_attempts: u8,
    repair_command: Option<&Path>,
    limits: FactoryLoopLimits,
) -> Result<FactoryFeedbackLoopOutcome, String> {
    let loop_started = Instant::now();
    // Charge configuration checks, input validation, and initial staging to
    // the same budget as submissions and repairs. Individual bounded file
    // operations are not forcibly interrupted, but no later phase starts once
    // this deadline has elapsed.
    let deadline = loop_started
        .checked_add(limits.total)
        .ok_or_else(|| "factory feedback loop deadline overflow".to_string())?;
    if !(1..=MAX_REPAIR_ATTEMPTS).contains(&max_attempts) {
        return Err(format!(
            "factory feedback max_attempts must be between 1 and {MAX_REPAIR_ATTEMPTS}"
        ));
    }
    if !(1..=600).contains(&timeout_seconds) {
        return Err("factory timeout must be between 1 and 600 seconds".into());
    }
    validate_endpoint(endpoint, allow_http_loopback)?;
    preflight_bearer_token(bearer_token_env)?;
    let repair_executable = repair_command.map(validate_repair_executable).transpose()?;

    // Snapshot one bounded read from one handle, validate those exact bytes,
    // and never consult the caller-controlled source path again.
    let initial_package = read_package(package_path)?;
    let initial_identity = validate_manufacturing_package(&initial_package)?;
    let initial_physical_profile = initial_identity.physical_profile.clone();
    let initial_dfm_profile = initial_identity.dfm_profile.clone();
    let workspace = TempfileBuilder::new()
        .prefix("pcbex-factory-loop-")
        .tempdir()
        .map_err(|error| format!("creating secure factory feedback workspace: {error}"))?;
    let mut current = snapshot_known_good(workspace.path(), "initial-", initial_package)?;
    let mut attempts = Vec::new();

    for attempt_number in 1..=max_attempts {
        let package_sha256 = sha256(&current.bytes);
        let package_bytes = current.bytes.len() as u64;
        let current_validation =
            validate_manufacturing_package(&current.bytes).and_then(|identity| {
                validate_expected_physical_profile(&identity, initial_physical_profile.as_ref())
                    .and_then(|()| {
                        validate_expected_dfm_profile(&identity, initial_dfm_profile.as_ref())
                    })
                    .map(|()| identity)
            });
        if let Err(error) = current_validation {
            let attempt = FactoryLoopAttempt {
                attempt: attempt_number,
                package_sha256,
                package_bytes,
                receipt: None,
                error: None,
                repair_command_ran: false,
            };
            return Ok(finish_failed_attempt(attempts, attempt, error, current));
        }
        let Some(network_timeout) = bounded_network_timeout(deadline, timeout_seconds) else {
            let attempt = FactoryLoopAttempt {
                attempt: attempt_number,
                package_sha256,
                package_bytes,
                receipt: None,
                error: None,
                repair_command_ran: false,
            };
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                total_timeout_error(limits.total),
                current,
            ));
        };
        let receipt = match submit_validated_factory_package_bytes(
            &current.bytes,
            endpoint,
            provider,
            bearer_token_env,
            network_timeout,
            allow_http_loopback,
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                let attempt = FactoryLoopAttempt {
                    attempt: attempt_number,
                    package_sha256,
                    package_bytes,
                    receipt: None,
                    error: None,
                    repair_command_ran: false,
                };
                return Ok(finish_failed_attempt(attempts, attempt, error, current));
            }
        };
        let passed = factory_feedback_passed(&receipt);
        let mut attempt = FactoryLoopAttempt {
            attempt: attempt_number,
            package_sha256,
            package_bytes,
            receipt: Some(receipt),
            error: None,
            repair_command_ran: false,
        };

        if Instant::now() >= deadline {
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                total_timeout_error(limits.total),
                current,
            ));
        }
        if passed {
            attempts.push(attempt);
            return Ok(finish_feedback_loop(true, attempts, None, current));
        }
        if attempt_number == max_attempts {
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                "factory DFM feedback did not pass before the attempt limit",
                current,
            ));
        }
        let Some(repair_executable) = repair_executable.as_deref() else {
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                "factory DFM feedback failed and no repair command was supplied",
                current,
            ));
        };
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                total_timeout_error(limits.total),
                current,
            ));
        };
        let repair_timeout = limits.repair.min(remaining);
        if repair_timeout.is_zero() {
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                total_timeout_error(limits.total),
                current,
            ));
        }
        let repair = run_repair_command(RepairCommandRequest {
            executable: repair_executable,
            current_package: &current,
            receipt: attempt
                .receipt
                .as_ref()
                .expect("a repair is attempted only after a receipt"),
            workspace: workspace.path(),
            timeout: repair_timeout,
            bearer_token_env,
            manufacturing_limits: limits.manufacturing,
            expected_physical_profile: initial_physical_profile.as_ref(),
            expected_dfm_profile: initial_dfm_profile.as_ref(),
        });
        attempt.repair_command_ran = repair.command_ran;
        let candidate = match repair.result {
            Ok(candidate) => candidate,
            Err(error) => {
                return Ok(finish_failed_attempt(attempts, attempt, error, current));
            }
        };
        if Instant::now() >= deadline {
            return Ok(finish_failed_attempt(
                attempts,
                attempt,
                total_timeout_error(limits.total),
                current,
            ));
        }
        let next = match snapshot_known_good(workspace.path(), "validated-", candidate) {
            Ok(next) => next,
            Err(error) => {
                return Ok(finish_failed_attempt(attempts, attempt, error, current));
            }
        };
        attempts.push(attempt);
        current = next;
    }

    unreachable!("the validated max_attempts bound makes the loop non-empty")
}

fn preflight_bearer_token(bearer_token_env: Option<&str>) -> Result<(), String> {
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
    }
    Ok(())
}

fn validate_repair_executable(path: &Path) -> Result<PathBuf, String> {
    if path.as_os_str().is_empty() {
        return Err("factory repair executable path must not be empty".into());
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        format!(
            "canonicalizing factory repair executable {}: {error}",
            path.display()
        )
    })?;
    let metadata = fs::metadata(&canonical).map_err(|error| {
        format!(
            "reading factory repair executable metadata {}: {error}",
            canonical.display()
        )
    })?;
    if !metadata.is_file() {
        return Err("factory repair executable must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err("factory repair executable must have an executable permission bit".into());
        }
    }
    Ok(canonical)
}

struct RepairCommandRequest<'a> {
    executable: &'a Path,
    current_package: &'a PackageSnapshot,
    receipt: &'a FactorySubmissionReceipt,
    workspace: &'a Path,
    timeout: Duration,
    bearer_token_env: Option<&'a str>,
    manufacturing_limits: ManufacturingLimits,
    expected_physical_profile: Option<&'a PhysicalProfileBinding>,
    expected_dfm_profile: Option<&'a DfmProfileBinding>,
}

fn run_repair_command(request: RepairCommandRequest<'_>) -> RepairCommandOutcome {
    let RepairCommandRequest {
        executable,
        current_package,
        receipt,
        workspace,
        timeout,
        bearer_token_env: _bearer_token_env,
        manufacturing_limits,
        expected_physical_profile,
        expected_dfm_profile,
    } = request;
    let deadline = match Instant::now().checked_add(timeout) {
        Some(deadline) => deadline,
        None => {
            return RepairCommandOutcome {
                command_ran: false,
                result: Err("factory repair command deadline overflow".into()),
            };
        }
    };
    let receipt_json = serde_json::to_vec_pretty(receipt)
        .map_err(|error| format!("serializing factory receipt for repair: {error}"));
    let receipt_json = match receipt_json {
        Ok(receipt_json) => receipt_json,
        Err(error) => {
            return RepairCommandOutcome {
                command_ran: false,
                result: Err(error),
            };
        }
    };
    let mut receipt_file = match tempfile::tempfile_in(workspace) {
        Ok(file) => file,
        Err(error) => {
            return RepairCommandOutcome {
                command_ran: false,
                result: Err(format!(
                    "creating factory repair receipt input file: {error}"
                )),
            };
        }
    };
    if let Err(error) = receipt_file
        .write_all(&receipt_json)
        .and_then(|()| receipt_file.flush())
        .and_then(|()| receipt_file.seek(SeekFrom::Start(0)).map(|_| ()))
    {
        return RepairCommandOutcome {
            command_ran: false,
            result: Err(format!("prewriting factory receipt for repair: {error}")),
        };
    }
    let output_package = match TempfileBuilder::new()
        .prefix("candidate-")
        .suffix(".zip")
        .tempfile_in(workspace)
    {
        Ok(output) => output,
        Err(error) => {
            return RepairCommandOutcome {
                command_ran: false,
                result: Err(format!("creating factory repair output file: {error}")),
            };
        }
    };
    let mut command = Command::new(executable);
    // Do not inherit caller state (especially the configured bearer secret).
    // The executable is canonical/absolute, and the only utility search path
    // is a fixed platform path rather than the caller's PATH.
    command
        .env_clear()
        .current_dir(workspace)
        .env("PCBEX_FACTORY_REPAIR_INPUT_PACKAGE", current_package.path())
        .env("PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE", output_package.path())
        .env("PCBEX_FACTORY_REPAIR_RECEIPT_JSON", "stdin");
    #[cfg(unix)]
    command.env("PATH", "/usr/bin:/bin").env("LC_ALL", "C");
    #[cfg(windows)]
    for variable in [
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "PATHEXT",
        "PATH",
        "TEMP",
        "TMP",
    ] {
        let carries_bearer_token = _bearer_token_env
            .is_some_and(|secret_name| windows_environment_name_matches(secret_name, variable));
        if !carries_bearer_token && let Some(value) = env::var_os(variable) {
            command.env(variable, value);
        }
    }

    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return RepairCommandOutcome {
            command_ran: false,
            result: Err(format!(
                "factory repair command exceeded {}",
                display_duration(timeout)
            )),
        };
    };
    if remaining.is_zero() {
        return RepairCommandOutcome {
            command_ran: false,
            result: Err(format!(
                "factory repair command exceeded {}",
                display_duration(timeout)
            )),
        };
    }

    let process_result = run_bounded_with_stdin_file(
        &mut command,
        receipt_file,
        ProcessLimits {
            timeout: remaining,
            stdout_bytes: FACTORY_REPAIR_PROCESS_STDOUT_LIMIT_BYTES,
            stderr_bytes: FACTORY_REPAIR_PROCESS_STDERR_LIMIT_BYTES,
        },
        None,
    );
    let command_ran = !matches!(
        &process_result,
        Err(ProcessError::InvalidTimeout { .. } | ProcessError::Spawn(_))
    );
    if !command_ran {
        let error = match process_result {
            Err(error @ ProcessError::InvalidTimeout { .. }) => error,
            Err(error @ ProcessError::Spawn(_)) => error,
            _ => unreachable!("the process error was classified as pre-spawn"),
        };
        return RepairCommandOutcome {
            command_ran: false,
            result: Err(map_repair_process_error(error, timeout)),
        };
    }
    if let Err(mutation) = verify_repair_input_unchanged(current_package) {
        let error = match process_result {
            Ok(output) if output.status.success() => mutation,
            Ok(output) => format!(
                "{mutation}; factory repair command failed with {}",
                output.status
            ),
            Err(process_error) => {
                format!(
                    "{mutation}; {}",
                    map_repair_process_error(process_error, timeout)
                )
            }
        };
        return RepairCommandOutcome {
            command_ran: true,
            result: Err(error),
        };
    }
    match process_result {
        Ok(output) if output.status.success() => {
            if let Err(error) = scan_manufacturing_workspace(
                workspace,
                manufacturing_limits,
                "factory repair workspace",
            ) {
                return RepairCommandOutcome {
                    command_ran: true,
                    result: Err(format!("scanning factory repair workspace: {error:#}")),
                };
            }
            RepairCommandOutcome {
                command_ran: true,
                result: read_validated_repair_output(
                    output_package.path(),
                    manufacturing_limits,
                    expected_physical_profile,
                    expected_dfm_profile,
                ),
            }
        }
        Ok(output) => RepairCommandOutcome {
            command_ran: true,
            result: Err(format!(
                "factory repair command failed with {}",
                output.status
            )),
        },
        Err(process_error) => RepairCommandOutcome {
            command_ran: true,
            result: Err(map_repair_process_error(process_error, timeout)),
        },
    }
}

fn map_repair_process_error(error: ProcessError, timeout_label: Duration) -> String {
    match error {
        ProcessError::InvalidTimeout { timeout } => format!(
            "factory repair command failed: subprocess timeout must be positive and representable: {}",
            display_duration(timeout)
        ),
        ProcessError::Spawn(source) => format!("starting factory repair command: {source}"),
        ProcessError::Timeout { .. } => format!(
            "factory repair command exceeded {}",
            display_duration(timeout_label)
        ),
        error => format!("factory repair command failed: {error}"),
    }
}

#[cfg(any(windows, test))]
fn windows_environment_name_matches(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

fn verify_repair_input_unchanged(snapshot: &PackageSnapshot) -> Result<(), String> {
    let path_metadata = fs::symlink_metadata(snapshot.path())
        .map_err(|error| format!("factory repair command modified its input package: {error}"))?;
    if !path_metadata.file_type().is_file() {
        return Err("factory repair command modified its input package path".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let original = snapshot.file.as_file().metadata().map_err(|error| {
            format!("reading factory repair input identity after command: {error}")
        })?;
        if original.dev() != path_metadata.dev() || original.ino() != path_metadata.ino() {
            return Err("factory repair command modified its input package by replacing it".into());
        }
    }
    let input_after = read_package(snapshot.path())
        .map_err(|error| format!("factory repair command modified its input package: {error}"))?;
    if input_after != snapshot.bytes {
        return Err("factory repair command modified its input package".into());
    }
    Ok(())
}

fn read_validated_repair_output(
    path: &Path,
    manufacturing_limits: ManufacturingLimits,
    expected_physical_profile: Option<&PhysicalProfileBinding>,
    expected_dfm_profile: Option<&DfmProfileBinding>,
) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("factory repair command did not write output package: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err("factory repair output must be a regular file".into());
    }
    if metadata.len() > manufacturing_limits.max_file_bytes {
        return Err(format!(
            "factory repair output exceeds the {}-byte file limit",
            manufacturing_limits.max_file_bytes
        ));
    }
    if metadata.len() > manufacturing_limits.max_archive_bytes {
        return Err(format!(
            "factory repair output exceeds the {}-byte archive limit",
            manufacturing_limits.max_archive_bytes
        ));
    }
    let package = read_package(path)
        .map_err(|error| format!("reading bounded factory repair output: {error}"))?;
    if package.len() as u64 > manufacturing_limits.max_file_bytes
        || package.len() as u64 > manufacturing_limits.max_archive_bytes
    {
        return Err(
            "factory repair output exceeded its manufacturing byte quota while being read".into(),
        );
    }
    let identity = validate_manufacturing_package(&package).map_err(|error| {
        format!("factory repair output is not a valid manufacturing package: {error}")
    })?;
    validate_expected_physical_profile(&identity, expected_physical_profile).map_err(|error| {
        format!("factory repair output is not a valid manufacturing package: {error}")
    })?;
    validate_expected_dfm_profile(&identity, expected_dfm_profile).map_err(|error| {
        format!("factory repair output is not a valid manufacturing package: {error}")
    })?;
    Ok(package)
}

fn snapshot_known_good(
    workspace: &Path,
    prefix: &str,
    bytes: Vec<u8>,
) -> Result<PackageSnapshot, String> {
    let mut file = TempfileBuilder::new()
        .prefix(prefix)
        .suffix(".zip")
        .tempfile_in(workspace)
        .map_err(|error| format!("creating secure factory package snapshot: {error}"))?;
    file.as_file_mut()
        .write_all(&bytes)
        .and_then(|()| file.as_file_mut().flush())
        .map_err(|error| format!("writing secure factory package snapshot: {error}"))?;
    Ok(PackageSnapshot { file, bytes })
}

fn bounded_network_timeout(deadline: Instant, configured_seconds: u64) -> Option<u64> {
    let remaining_seconds = deadline.checked_duration_since(Instant::now())?.as_secs();
    if remaining_seconds == 0 {
        None
    } else {
        Some(configured_seconds.min(remaining_seconds))
    }
}

fn finish_failed_attempt(
    mut attempts: Vec<FactoryLoopAttempt>,
    mut attempt: FactoryLoopAttempt,
    failure: impl AsRef<str>,
    package: PackageSnapshot,
) -> FactoryFeedbackLoopOutcome {
    let failure = bounded_loop_error(failure.as_ref());
    attempt.error = Some(failure.clone());
    attempts.push(attempt);
    finish_feedback_loop(false, attempts, Some(failure), package)
}

fn finish_feedback_loop(
    passed: bool,
    attempts: Vec<FactoryLoopAttempt>,
    failure: Option<String>,
    package: PackageSnapshot,
) -> FactoryFeedbackLoopOutcome {
    let final_package_sha256 = sha256(&package.bytes);
    let final_package_bytes = package.bytes.len() as u64;
    FactoryFeedbackLoopOutcome {
        report: FactoryFeedbackLoopReport {
            schema_version: 1,
            passed,
            attempts,
            final_package_sha256,
            final_package_bytes,
            failure,
        },
        final_package: package.into_bytes(),
    }
}

fn bounded_loop_error(error: &str) -> String {
    let error = error.trim();
    let error = if error.is_empty() {
        "factory feedback loop failed"
    } else {
        error
    };
    error.chars().take(MAX_LOOP_ERROR_CHARS).collect()
}

fn total_timeout_error(total: Duration) -> String {
    format!("factory feedback loop exceeded {}", display_duration(total))
}

fn display_duration(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        format!("{} seconds", duration.as_secs())
    } else {
        format!("{} milliseconds", duration.as_millis())
    }
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
    let package = read_package(package_path)?;
    submit_factory_package_bytes(
        &package,
        endpoint,
        provider,
        bearer_token_env,
        timeout_seconds,
        allow_http_loopback,
    )
}

fn submit_factory_package_bytes(
    package: &[u8],
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
    validate_manufacturing_package(package)?;
    submit_validated_factory_package_bytes(
        package,
        endpoint,
        provider,
        bearer_token_env,
        timeout_seconds,
        allow_http_loopback,
    )
}

fn submit_validated_factory_package_bytes(
    package: &[u8],
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
    let package_sha256 = sha256(package);
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
    let bearer_token = if let Some(variable) = bearer_token_env {
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
        Some(token)
    } else {
        None
    };
    let mut response = call
        .send(package)
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
    if bearer_token.as_deref().is_some_and(|token| {
        response_contains_bearer_token(&response_bytes, &response_value, token)
    }) {
        return Err("factory response reflected bearer credentials".into());
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

fn validate_factory_text(
    value: &str,
    label: &str,
    maximum: usize,
    require_trimmed: bool,
) -> Result<(), String> {
    if value.is_empty()
        || value.chars().count() > maximum
        || value.contains('\0')
        || (require_trimmed && value.trim() != value)
    {
        return Err(format!(
            "{label} must contain 1 to {maximum} trimmed characters"
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManufacturingDescriptor {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManufacturingTools {
    kicad_cli: String,
    kicad_cli_about_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManufacturingCounts {
    total: u64,
    bom: u64,
    placement: u64,
    dnp: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManufacturingManifest {
    schema_version: u32,
    engine: String,
    engine_version: String,
    tools: ManufacturingTools,
    input: ManufacturingDescriptor,
    project_inputs: Vec<ManufacturingDescriptor>,
    parts: ManufacturingCounts,
    artifacts: Vec<ManufacturingDescriptor>,
    archive: String,
    #[serde(default)]
    physical_profile: Option<PhysicalProfileBinding>,
    #[serde(default)]
    dfm_profile: Option<DfmProfileBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManufacturingPackageIdentity {
    pub(crate) input_path: String,
    pub(crate) input_bytes: u64,
    pub(crate) input_sha256: String,
    pub(crate) physical_profile: Option<PhysicalProfileBinding>,
    pub(crate) dfm_profile: Option<DfmProfileBinding>,
}

/// Exact evidence retained while performing the full manufacturing-package
/// validation. The final-BOM and final-CPL verifiers need the validated
/// manifest and exact CSV bytes, not a second, weaker ZIP parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManufacturingPackageDetails {
    pub(crate) identity: ManufacturingPackageIdentity,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) bom_bytes: Vec<u8>,
    pub(crate) cpl_bytes: Vec<u8>,
    pub(crate) manifest_parts_total: u64,
    pub(crate) manifest_parts_bom: u64,
    pub(crate) manifest_parts_placement: u64,
}

fn validate_expected_physical_profile(
    identity: &ManufacturingPackageIdentity,
    expected: Option<&PhysicalProfileBinding>,
) -> Result<(), String> {
    if identity.physical_profile.as_ref() != expected {
        return Err("factory package physical profile binding changed during repair".into());
    }
    Ok(())
}

fn validate_expected_dfm_profile(
    identity: &ManufacturingPackageIdentity,
    expected: Option<&DfmProfileBinding>,
) -> Result<(), String> {
    if identity.dfm_profile.as_ref() != expected {
        return Err("factory package DFM profile binding changed during repair".into());
    }
    Ok(())
}

fn read_package(package_path: &Path) -> Result<Vec<u8>, String> {
    let package = crate::bounded_io::read_with_limit(package_path, MAX_PACKAGE_BYTES).map_err(
        |error| {
            let detail = error.to_string();
            let context = format!("reading factory package {}", package_path.display());
            if detail.contains("exceeds") {
                format!(
                    "{context}: factory package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
                )
            } else if detail.to_ascii_lowercase().contains("symlink") {
                format!(
                    "{context}: factory package path must be a real regular file, not a symlink: {detail}"
                )
            } else if detail.contains("regular non-symlink file") {
                format!("{context}: factory package path must be a regular file: {detail}")
            } else {
                format!("{context}: {detail}")
            }
        },
    )?;
    if package.is_empty() {
        return Err(format!(
            "factory package must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }
    Ok(package)
}

pub(crate) fn validate_manufacturing_package(
    package: &[u8],
) -> Result<ManufacturingPackageIdentity, String> {
    validate_manufacturing_package_with_expanded_limit(package, MAX_ARCHIVE_UNCOMPRESSED_BYTES)
}

pub(crate) fn validate_manufacturing_package_details(
    package: &[u8],
) -> Result<ManufacturingPackageDetails, String> {
    validate_manufacturing_package_details_with_expanded_limit(
        package,
        MAX_ARCHIVE_UNCOMPRESSED_BYTES,
    )
}

fn validate_manufacturing_package_with_expanded_limit(
    package: &[u8],
    max_expanded_bytes: u64,
) -> Result<ManufacturingPackageIdentity, String> {
    validate_manufacturing_package_details_with_expanded_limit(package, max_expanded_bytes)
        .map(|details| details.identity)
}

fn validate_manufacturing_package_details_with_expanded_limit(
    package: &[u8],
    max_expanded_bytes: u64,
) -> Result<ManufacturingPackageDetails, String> {
    let central_directory = validate_classic_zip_directory(package)?;
    if central_directory.entries > MAX_ARCHIVE_ENTRIES {
        return Err(format!(
            "factory package contains more than {MAX_ARCHIVE_ENTRIES} ZIP entries"
        ));
    }
    let mut archive = ZipArchive::new(Cursor::new(package))
        .map_err(|error| format!("factory package is not a valid ZIP archive: {error}"))?;
    if archive.offset() != 0 || archive.central_directory_start() != central_directory.offset as u64
    {
        return Err("factory package ZIP parser and raw central-directory views differ".into());
    }
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(format!(
            "factory package contains more than {MAX_ARCHIVE_ENTRIES} ZIP entries"
        ));
    }
    if central_directory.entries != archive.len() {
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
    reject_duplicate_json_keys(&manifest_bytes).map_err(|error| {
        format!("factory package manifest.json contains duplicate or invalid JSON keys: {error:#}")
    })?;
    let manifest_value: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("factory package manifest.json is not valid JSON: {error}"))?;
    let manifest: ManufacturingManifest = serde_json::from_value(manifest_value.clone())
        .map_err(|error| format!("factory package manifest.json is not valid JSON: {error}"))?;
    let physical_profile_present = manifest_value
        .as_object()
        .is_some_and(|object| object.contains_key("physical_profile"));
    let dfm_profile_present = manifest_value
        .as_object()
        .is_some_and(|object| object.contains_key("dfm_profile"));
    let (physical_profile, dfm_profile) = match (
        manifest.schema_version,
        physical_profile_present,
        manifest.physical_profile.as_ref(),
        dfm_profile_present,
        manifest.dfm_profile.as_ref(),
    ) {
        (1, false, None, false, None) => (None, None),
        (1, true, _, _, _) => {
            return Err(
                "factory package manifest.json schema_version 1 must omit physical_profile".into(),
            );
        }
        (1, false, None, true, _) => {
            return Err(
                "factory package manifest.json schema_version 1 must omit dfm_profile".into(),
            );
        }
        (2, false, _, false, _) => {
            return Err(
                "factory package manifest.json schema_version 2 requires physical_profile".into(),
            );
        }
        (2, true, Some(binding), false, None) => {
            validate_physical_profile_binding(binding).map_err(|error| {
                format!("factory package manifest.json physical_profile is invalid: {error:#}")
            })?;
            (Some(binding.clone()), None)
        }
        (2, true, _, true, _) => {
            return Err(
                "factory package manifest.json schema_version 2 must omit dfm_profile".into(),
            );
        }
        (2, true, None, false, _) => {
            return Err(
                "factory package manifest.json schema_version 2 requires physical_profile".into(),
            );
        }
        (3, false, None, true, Some(binding)) => {
            validate_dfm_profile_binding(binding).map_err(|error| {
                format!("factory package manifest.json dfm_profile is invalid: {error:#}")
            })?;
            (None, Some(binding.clone()))
        }
        (3, true, _, _, _) => {
            return Err(
                "factory package manifest.json schema_version 3 must omit physical_profile".into(),
            );
        }
        (3, false, None, false, _) | (3, false, None, true, None) => {
            return Err(
                "factory package manifest.json schema_version 3 requires dfm_profile".into(),
            );
        }
        _ => {
            return Err(
                "factory package manifest.json schema_version must be 1 without profiles, 2 with physical_profile, or 3 with dfm_profile"
                    .into(),
            );
        }
    };
    if manifest.engine != "pcbex" {
        return Err("factory package manifest.json must name pcbex as its engine".into());
    }
    validate_manifest_text(&manifest.engine_version, "engine_version")?;
    validate_manifest_text(&manifest.tools.kicad_cli, "tools.kicad_cli")?;
    if !is_sha256(&manifest.tools.kicad_cli_about_sha256) {
        return Err("factory package manifest.json tools.kicad_cli_about_sha256 is invalid".into());
    }
    if manifest.parts.bom > manifest.parts.total
        || manifest.parts.placement > manifest.parts.total
        || manifest.parts.dnp > manifest.parts.total
    {
        return Err("factory package manifest.json contains invalid part counts".into());
    }
    if manifest.parts.total > MAX_MANUFACTURING_PARTS as u64 {
        return Err(format!(
            "factory package manifest.json total part count exceeds {MAX_MANUFACTURING_PARTS}"
        ));
    }
    if manifest.archive != "manufacturing.zip" {
        return Err(
            "factory package manifest.json must name manufacturing.zip as its archive".into(),
        );
    }

    validate_manifest_descriptor(&manifest.input, "input")?;
    let identity = ManufacturingPackageIdentity {
        input_path: manifest.input.path.clone(),
        input_bytes: manifest.input.bytes,
        input_sha256: manifest.input.sha256.clone(),
        physical_profile,
        dfm_profile,
    };
    let manifest_parts_total = manifest.parts.total;
    let expected_bom_quantity = manifest.parts.bom;
    let expected_placement_rows = manifest.parts.placement;
    let mut provenance_paths = BTreeSet::from([manifest.input.path.clone()]);
    let mut provenance_portable_paths =
        BTreeSet::from([portable_manufacturing_name_key(&manifest.input.path)]);
    for descriptor in &manifest.project_inputs {
        validate_manifest_descriptor(descriptor, "project input")?;
        if !provenance_paths.insert(descriptor.path.clone())
            || !provenance_portable_paths.insert(portable_manufacturing_name_key(&descriptor.path))
        {
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
    let mut expected_portable_paths = BTreeSet::new();
    for descriptor in manifest.artifacts {
        validate_manifest_descriptor(&descriptor, "artifact")?;
        if descriptor.path.eq_ignore_ascii_case("manifest.json")
            || descriptor.path.eq_ignore_ascii_case("manufacturing.zip")
        {
            return Err(
                "factory package artifacts must not include manifest.json or manufacturing.zip"
                    .into(),
            );
        }
        if !expected_portable_paths.insert(portable_manufacturing_name_key(&descriptor.path))
            || expected
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
    validate_manifest_path_domains(&provenance_paths, &expected)?;
    let gerber_job = validate_required_manufacturing_artifacts(&expected)?;
    let mut seen = BTreeSet::new();
    let mut seen_portable = BTreeSet::new();
    let mut total_uncompressed = 0_u64;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|error| format!("reading factory package ZIP entry {index}: {error}"))?;
        if entry.name_raw() != entry.name().as_bytes() {
            return Err(format!(
                "factory package ZIP entry {index} raw and decoded names differ"
            ));
        }
        let name = entry.name().to_string();
        if !is_safe_manifest_path(&name) {
            return Err(format!(
                "factory package contains unsafe ZIP entry path {name:?}"
            ));
        }
        if !seen.insert(name.clone())
            || !seen_portable.insert(portable_manufacturing_name_key(&name))
        {
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
        let (actual_bytes, actual_hash) = hash_zip_entry(&mut entry, &name)?;
        // ZIP size fields are attacker-controlled metadata.  Aggregate the
        // bytes that were actually decompressed instead of trusting the
        // central-directory declaration.
        add_archive_size_with_limit(
            &mut total_uncompressed,
            actual_bytes,
            &name,
            max_expanded_bytes,
        )?;
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
    validate_gerber_job(package, &gerber_job, &expected)?;
    validate_bom_csv(package, expected_bom_quantity)?;
    validate_cpl_csv(package, expected_placement_rows)?;
    let bom_bytes = read_validated_zip_entry(package, "bom.csv", MAX_PACKAGE_BYTES)?;
    let cpl_bytes = read_validated_zip_entry(package, "cpl.csv", MAX_PACKAGE_BYTES)?;
    Ok(ManufacturingPackageDetails {
        identity,
        manifest_bytes,
        bom_bytes,
        cpl_bytes,
        manifest_parts_total,
        manifest_parts_bom: expected_bom_quantity,
        manifest_parts_placement: expected_placement_rows,
    })
}

fn validate_manifest_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.trim() != value || value.chars().count() > 256 {
        return Err(format!(
            "factory package manifest.json {field} must contain 1 to 256 trimmed characters"
        ));
    }
    Ok(())
}

fn validate_required_manufacturing_artifacts(
    artifacts: &BTreeMap<String, (u64, String)>,
) -> Result<String, String> {
    for required in ["bom.csv", "cpl.csv", "drc.rpt"] {
        if !artifacts.contains_key(required) {
            return Err(format!(
                "factory package manifest.json is missing required artifact {required}"
            ));
        }
    }
    if !artifacts.keys().any(|name| has_extension(name, "drl")) {
        return Err("factory package manifest.json must contain an Excellon drill artifact".into());
    }
    let gerber_jobs = artifacts
        .keys()
        .filter(|name| name.ends_with("-job.gbrjob"))
        .cloned()
        .collect::<Vec<_>>();
    if gerber_jobs.len() != 1 {
        return Err(
            "factory package manifest.json must contain exactly one Gerber job artifact".into(),
        );
    }
    for name in artifacts.keys() {
        if matches!(name.as_str(), "bom.csv" | "cpl.csv" | "drc.rpt")
            || has_extension(name, "drl")
            || name.ends_with("-job.gbrjob")
            || is_gerber_artifact(name)
        {
            continue;
        }
        return Err(format!(
            "factory package manifest.json contains unsupported manufacturing artifact {name}"
        ));
    }
    Ok(gerber_jobs[0].clone())
}

fn validate_bom_csv(package: &[u8], expected_quantity: u64) -> Result<(), String> {
    let mut quantity = 0_u64;
    let mut records = 0_u64;
    let mut header_seen = false;
    validate_zip_csv(package, "bom.csv", 7, |index, fields, quoted| {
        if index == 0 {
            header_seen = true;
            validate_csv_header(
                &fields,
                quoted,
                &[
                    "Comment",
                    "Designator",
                    "Footprint",
                    "Quantity",
                    "MPN",
                    "Layer",
                    "Type",
                ],
                "BOM",
            )?;
            return Ok(());
        }
        records = records
            .checked_add(1)
            .ok_or_else(|| "factory BOM row count overflow".to_string())?;
        let comment = csv_text(&fields[0], "BOM Comment")?;
        validate_bom_text(comment, "BOM Comment", true)?;
        let designator = csv_text(&fields[1], "BOM Designator")?;
        validate_bom_text(designator, "BOM Designator", true)?;
        let footprint = csv_text(&fields[2], "BOM Footprint")?;
        validate_bom_text(footprint, "BOM Footprint", true)?;
        let row_quantity = parse_positive_quantity(&fields[3])?;
        quantity = quantity
            .checked_add(row_quantity)
            .ok_or_else(|| "factory BOM quantity overflow".to_string())?;
        let mpn = csv_text(&fields[4], "BOM MPN")?;
        if !mpn.is_empty() {
            validate_bom_text(mpn, "BOM MPN", false)?;
        }
        if fields[5].as_slice() != b"F" && fields[5].as_slice() != b"B" {
            return Err("factory BOM Layer must be exactly F or B".into());
        }
        if fields[6].as_slice() != b"SMD" && fields[6].as_slice() != b"THT" {
            return Err("factory BOM Type must be exactly SMD or THT".into());
        }
        Ok(())
    })?;
    if !header_seen {
        return Err("factory bom.csv CSV must contain its exact header".into());
    }
    if records == 0 && expected_quantity != 0 {
        return Err(format!(
            "factory bom.csv quantity {expected_quantity} does not match the empty BOM"
        ));
    }
    if quantity != expected_quantity {
        return Err(format!(
            "factory bom.csv quantity {quantity} does not match manifest.parts.bom {expected_quantity}"
        ));
    }
    Ok(())
}

fn validate_cpl_csv(package: &[u8], expected_rows: u64) -> Result<(), String> {
    let mut rows = 0_u64;
    let mut designators = BTreeSet::new();
    let mut header_seen = false;
    validate_zip_csv(package, "cpl.csv", 5, |index, fields, quoted| {
        if index == 0 {
            header_seen = true;
            validate_csv_header(
                &fields,
                quoted,
                &[
                    "Designator",
                    "Mid X (mm)",
                    "Mid Y (mm)",
                    "Rotation",
                    "Layer",
                ],
                "CPL",
            )?;
            return Ok(());
        }
        rows = rows
            .checked_add(1)
            .ok_or_else(|| "factory CPL row count overflow".to_string())?;
        let designator = csv_text(&fields[0], "CPL Designator")?;
        validate_bom_text(designator, "CPL Designator", true)?;
        if !designators.insert(designator.to_string()) {
            return Err(format!(
                "factory CPL contains duplicate Designator {designator:?}"
            ));
        }
        parse_scaled_decimal(&fields[1], 1_000_000, 6, "CPL Mid X (mm)")?;
        parse_scaled_decimal(&fields[2], 1_000_000, 6, "CPL Mid Y (mm)")?;
        parse_scaled_decimal(&fields[3], 1_000, 3, "CPL Rotation")?;
        if fields[4].as_slice() != b"F" && fields[4].as_slice() != b"B" {
            return Err("factory CPL Layer must be exactly F or B".into());
        }
        Ok(())
    })?;
    if !header_seen {
        return Err("factory cpl.csv CSV must contain its exact header".into());
    }
    if rows != expected_rows {
        return Err(format!(
            "factory cpl.csv row count {rows} does not match manifest.parts.placement {expected_rows}"
        ));
    }
    Ok(())
}

fn validate_csv_header(
    fields: &[Vec<u8>],
    quoted: bool,
    expected: &[&str],
    kind: &str,
) -> Result<(), String> {
    if quoted
        || fields.len() != expected.len()
        || fields
            .iter()
            .zip(expected)
            .any(|(actual, expected)| actual.as_slice() != expected.as_bytes())
    {
        return Err(format!(
            "factory {kind} CSV header must be exactly {}",
            expected.join(",")
        ));
    }
    Ok(())
}

fn csv_text<'a>(bytes: &'a [u8], field: &str) -> Result<&'a str, String> {
    std::str::from_utf8(bytes).map_err(|_| format!("factory {field} contains invalid UTF-8"))
}

fn validate_bom_text(value: &str, field: &str, require_nonempty: bool) -> Result<(), String> {
    if require_nonempty && value.is_empty() {
        return Err(format!("factory {field} must be nonempty"));
    }
    if value.contains('\0') {
        return Err(format!(
            "factory {field} contains unsafe control characters"
        ));
    }
    Ok(())
}

fn parse_positive_quantity(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err("factory BOM Quantity must be a positive checked integer".into());
    }
    let quantity = std::str::from_utf8(bytes)
        .map_err(|_| "factory BOM Quantity must be a positive checked integer".to_string())?
        .parse::<u64>()
        .map_err(|_| "factory BOM Quantity must be a positive checked integer".to_string())?;
    if quantity == 0 {
        return Err("factory BOM Quantity must be a positive checked integer".into());
    }
    Ok(quantity)
}

fn parse_scaled_decimal(
    bytes: &[u8],
    scale: u128,
    precision: usize,
    field: &str,
) -> Result<i64, String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| format!("factory {field} must be a finite decimal"))?;
    let (negative, unsigned) = match text.strip_prefix('-') {
        Some(value) => (true, value),
        None => (false, text),
    };
    if unsigned.is_empty()
        || unsigned.starts_with('+')
        || unsigned.contains(['e', 'E'])
        || unsigned.ends_with('.')
    {
        return Err(format!("factory {field} must be a finite decimal"));
    }
    let mut pieces = unsigned.split('.');
    let whole = pieces.next().unwrap_or_default();
    let fraction = pieces.next().unwrap_or_default();
    if pieces.next().is_some()
        || whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > precision
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("factory {field} must be a finite decimal"));
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| format!("factory {field} is outside the checked range"))?;
    let whole = whole
        .checked_mul(scale)
        .ok_or_else(|| format!("factory {field} is outside the checked range"))?;
    let fraction_value = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u128>()
            .map_err(|_| format!("factory {field} must be a finite decimal"))?
            .checked_mul(10_u128.pow((precision - fraction.len()) as u32))
            .ok_or_else(|| format!("factory {field} is outside the checked range"))?
    };
    let magnitude = whole
        .checked_add(fraction_value)
        .ok_or_else(|| format!("factory {field} is outside the checked range"))?;
    let maximum = if negative {
        (i64::MAX as u128) + 1
    } else {
        i64::MAX as u128
    };
    if magnitude > maximum {
        return Err(format!("factory {field} is outside the checked range"));
    }
    if negative {
        if magnitude == (i64::MAX as u128) + 1 {
            Ok(i64::MIN)
        } else {
            Ok(-(magnitude as i64))
        }
    } else {
        Ok(magnitude as i64)
    }
}

fn validate_zip_csv(
    package: &[u8],
    name: &str,
    expected_fields: usize,
    mut on_record: impl FnMut(usize, Vec<Vec<u8>>, bool) -> Result<(), String>,
) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(package))
        .map_err(|error| format!("reopening factory package ZIP archive: {error}"))?;
    let mut entry = archive
        .by_name(name)
        .map_err(|_| format!("factory package is missing {name}"))?;
    if !entry.is_file() {
        return Err(format!(
            "factory package CSV entry {name} must be a regular file"
        ));
    }
    if entry.size() > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory package CSV entry {name} exceeds size limit"
        ));
    }
    parse_csv_reader(&mut entry, name, expected_fields, &mut on_record)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CsvState {
    FieldStart,
    Unquoted,
    Quoted,
    AfterQuote,
    RecordCr,
}

fn parse_csv_reader<R: Read, F: FnMut(usize, Vec<Vec<u8>>, bool) -> Result<(), String>>(
    reader: &mut R,
    name: &str,
    expected_fields: usize,
    callback: &mut F,
) -> Result<(), String> {
    if expected_fields == 0 {
        return Err(format!("factory {name} CSV field count is invalid"));
    }
    let mut buffer = [0_u8; 64 * 1024];
    let mut fields = Vec::<Vec<u8>>::new();
    let mut field = Vec::<u8>::new();
    let mut state = CsvState::FieldStart;
    let mut record_quoted = false;
    let mut record_started = false;
    let mut record_bytes = 0_usize;
    let mut record_index = 0_usize;

    let mut finish_record = |fields: &mut Vec<Vec<u8>>,
                             field: &mut Vec<u8>,
                             record_quoted: &mut bool,
                             record_started: &mut bool,
                             record_bytes: &mut usize,
                             record_index: &mut usize|
     -> Result<(), String> {
        fields.push(std::mem::take(field));
        if fields.len() != expected_fields {
            return Err(format!(
                "factory {name} CSV record {} has {} fields; expected {expected_fields}",
                *record_index + 1,
                fields.len()
            ));
        }
        if *record_index > MAX_MANUFACTURING_PARTS {
            return Err(format!(
                "factory {name} CSV contains more than {MAX_MANUFACTURING_PARTS} data rows"
            ));
        }
        callback(*record_index, std::mem::take(fields), *record_quoted)
            .map_err(|error| format!("factory package CSV entry {name}: {error}"))?;
        *record_index += 1;
        *record_quoted = false;
        *record_started = false;
        *record_bytes = 0;
        Ok(())
    };

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("reading factory package CSV entry {name}: {error}"))?;
        if read == 0 {
            break;
        }
        for &byte in &buffer[..read] {
            record_bytes = record_bytes
                .checked_add(1)
                .ok_or_else(|| format!("factory {name} CSV record byte count overflow"))?;
            if record_bytes > MAX_CSV_RECORD_BYTES {
                return Err(format!(
                    "factory {name} CSV record exceeds {MAX_CSV_RECORD_BYTES} bytes"
                ));
            }
            if byte == 0 {
                return Err(format!("factory {name} CSV contains NUL"));
            }
            if state == CsvState::RecordCr {
                if byte != b'\n' {
                    return Err(format!("factory {name} CSV CR must be followed by LF"));
                }
                finish_record(
                    &mut fields,
                    &mut field,
                    &mut record_quoted,
                    &mut record_started,
                    &mut record_bytes,
                    &mut record_index,
                )?;
                state = CsvState::FieldStart;
                continue;
            }
            match state {
                CsvState::FieldStart => match byte {
                    b'"' => {
                        state = CsvState::Quoted;
                        record_quoted = true;
                        record_started = true;
                    }
                    b',' => {
                        if fields.len() >= expected_fields {
                            return Err(format!("factory {name} CSV record has too many fields"));
                        }
                        fields.push(std::mem::take(&mut field));
                        record_started = true;
                    }
                    b'\n' => {
                        finish_record(
                            &mut fields,
                            &mut field,
                            &mut record_quoted,
                            &mut record_started,
                            &mut record_bytes,
                            &mut record_index,
                        )?;
                        state = CsvState::FieldStart;
                    }
                    b'\r' => state = CsvState::RecordCr,
                    _ => {
                        field.push(byte);
                        state = CsvState::Unquoted;
                        record_started = true;
                    }
                },
                CsvState::Unquoted => match byte {
                    b',' => {
                        if fields.len() >= expected_fields {
                            return Err(format!("factory {name} CSV record has too many fields"));
                        }
                        fields.push(std::mem::take(&mut field));
                        state = CsvState::FieldStart;
                    }
                    b'\n' => {
                        finish_record(
                            &mut fields,
                            &mut field,
                            &mut record_quoted,
                            &mut record_started,
                            &mut record_bytes,
                            &mut record_index,
                        )?;
                        state = CsvState::FieldStart;
                    }
                    b'\r' => state = CsvState::RecordCr,
                    b'"' => {
                        return Err(format!("factory {name} CSV contains an unescaped quote"));
                    }
                    _ => field.push(byte),
                },
                CsvState::Quoted => match byte {
                    b'"' => state = CsvState::AfterQuote,
                    _ => field.push(byte),
                },
                CsvState::AfterQuote => match byte {
                    b'"' => {
                        field.push(byte);
                        state = CsvState::Quoted;
                    }
                    b',' => {
                        if fields.len() >= expected_fields {
                            return Err(format!("factory {name} CSV record has too many fields"));
                        }
                        fields.push(std::mem::take(&mut field));
                        state = CsvState::FieldStart;
                    }
                    b'\n' => {
                        finish_record(
                            &mut fields,
                            &mut field,
                            &mut record_quoted,
                            &mut record_started,
                            &mut record_bytes,
                            &mut record_index,
                        )?;
                        state = CsvState::FieldStart;
                    }
                    b'\r' => state = CsvState::RecordCr,
                    _ => {
                        return Err(format!("factory {name} CSV has data after a closing quote"));
                    }
                },
                CsvState::RecordCr => unreachable!(),
            }
        }
    }

    match state {
        CsvState::Quoted => Err(format!(
            "factory {name} CSV has an unterminated quoted field"
        )),
        CsvState::RecordCr => Err(format!("factory {name} CSV CR must be followed by LF")),
        CsvState::AfterQuote | CsvState::Unquoted => finish_record(
            &mut fields,
            &mut field,
            &mut record_quoted,
            &mut record_started,
            &mut record_bytes,
            &mut record_index,
        ),
        CsvState::FieldStart => {
            if record_started || !fields.is_empty() {
                finish_record(
                    &mut fields,
                    &mut field,
                    &mut record_quoted,
                    &mut record_started,
                    &mut record_bytes,
                    &mut record_index,
                )?;
            }
            Ok(())
        }
    }
}

fn validate_manifest_path_domains(
    provenance: &BTreeSet<String>,
    artifacts: &BTreeMap<String, (u64, String)>,
) -> Result<(), String> {
    let provenance_keys = provenance
        .iter()
        .map(|path| portable_manufacturing_name_key(path))
        .collect::<BTreeSet<_>>();
    if let Some(path) = artifacts
        .keys()
        .find(|path| provenance_keys.contains(&portable_manufacturing_name_key(path)))
    {
        return Err(format!(
            "factory package path {path} must not identify both provenance and an artifact"
        ));
    }
    Ok(())
}

fn validate_gerber_job(
    package: &[u8],
    job_name: &str,
    artifacts: &BTreeMap<String, (u64, String)>,
) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(package))
        .map_err(|error| format!("reopening factory package ZIP archive: {error}"))?;
    let job = archive
        .by_name(job_name)
        .map_err(|_| format!("factory package is missing Gerber job entry {job_name}"))?;
    let mut job_bytes = Vec::new();
    job.take(MAX_MANIFEST_BYTES.saturating_add(1))
        .read_to_end(&mut job_bytes)
        .map_err(|error| format!("reading factory package Gerber job {job_name}: {error}"))?;
    if job_bytes.is_empty() || job_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(format!(
            "factory package Gerber job must contain 1 to {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    let job: Value = serde_json::from_slice(&job_bytes)
        .map_err(|error| format!("factory package Gerber job is not valid JSON: {error}"))?;
    let layer_count = job
        .get("GeneralSpecs")
        .and_then(|value| value.get("LayerNumber"))
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            "factory package Gerber job is missing GeneralSpecs.LayerNumber".to_string()
        })?;
    if !(2..=32).contains(&layer_count) {
        return Err("factory package Gerber job has an invalid copper layer count".into());
    }
    let file_attributes = job
        .get("FilesAttributes")
        .and_then(Value::as_array)
        .ok_or_else(|| "factory package Gerber job FilesAttributes must be an array".to_string())?;
    if file_attributes.is_empty() || file_attributes.len() > MAX_ARCHIVE_ENTRIES {
        return Err("factory package Gerber job has an invalid FilesAttributes count".into());
    }

    let mut job_paths = BTreeSet::new();
    let mut copper_layers = BTreeMap::<u64, String>::new();
    let mut profile = false;
    let mut top_mask = false;
    let mut bottom_mask = false;
    let mut top_legend = false;
    let mut bottom_legend = false;
    for attribute in file_attributes {
        let path = attribute
            .get("Path")
            .and_then(Value::as_str)
            .ok_or_else(|| "factory package Gerber job file Path must be a string".to_string())?;
        let function = attribute
            .get("FileFunction")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                "factory package Gerber job FileFunction must be a string".to_string()
            })?;
        if !is_safe_manifest_path(path) || !job_paths.insert(path.to_string()) {
            return Err(format!(
                "factory package Gerber job contains unsafe or duplicate path {path:?}"
            ));
        }
        if !artifacts.contains_key(path) || !is_gerber_artifact(path) {
            return Err(format!(
                "factory package Gerber job references undeclared Gerber artifact {path}"
            ));
        }
        let components = function.split(',').collect::<Vec<_>>();
        match components.as_slice() {
            ["Copper", layer, side] => {
                let index = layer
                    .strip_prefix('L')
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| {
                        format!("factory package Gerber job has invalid copper function {function}")
                    })?;
                if !(1..=layer_count).contains(&index)
                    || copper_layers.insert(index, (*side).to_string()).is_some()
                {
                    return Err(format!(
                        "factory package Gerber job has duplicate or out-of-range copper layer {layer}"
                    ));
                }
            }
            ["Profile"] => profile = true,
            ["SolderMask", "Top"] => top_mask = true,
            ["SolderMask", "Bot"] => bottom_mask = true,
            ["Legend", "Top"] => top_legend = true,
            ["Legend", "Bot"] => bottom_legend = true,
            _ => {}
        }
    }
    if copper_layers.len() as u64 != layer_count
        || copper_layers.get(&1).map(String::as_str) != Some("Top")
        || copper_layers.get(&layer_count).map(String::as_str) != Some("Bot")
        || !(1..=layer_count).all(|index| copper_layers.contains_key(&index))
    {
        return Err("factory package Gerber job does not bind every declared copper layer".into());
    }
    if !profile || !top_mask || !bottom_mask || !top_legend || !bottom_legend {
        return Err("factory package Gerber job is missing profile, mask, or legend layers".into());
    }
    for path in artifacts.keys().filter(|path| is_gerber_artifact(path)) {
        if !job_paths.contains(path) {
            return Err(format!(
                "factory package Gerber artifact {path} is not bound by its Gerber job"
            ));
        }
    }
    Ok(())
}

fn has_extension(path: &str, expected: &str) -> bool {
    Path::new(path)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn is_gerber_artifact(path: &str) -> bool {
    let Some(extension) = Path::new(path).extension().and_then(|value| value.to_str()) else {
        return false;
    };
    let extension = extension.to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "gbr" | "gtl" | "gbl" | "gtp" | "gbp" | "gts" | "gbs" | "gto" | "gbo"
    ) || extension.strip_prefix('g').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
    }) || extension.strip_prefix("gm").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
    })
}

fn add_archive_size_with_limit(
    total: &mut u64,
    size: u64,
    name: &str,
    max_expanded_bytes: u64,
) -> Result<(), String> {
    *total = total
        .checked_add(size)
        .ok_or_else(|| format!("factory package ZIP entry {name} size overflow"))?;
    if *total > max_expanded_bytes {
        return Err(format!(
            "factory package decompressed artifact bytes exceed {max_expanded_bytes}"
        ));
    }
    Ok(())
}

struct ClassicZipDirectory {
    entries: usize,
    offset: usize,
}

fn validate_classic_zip_directory(package: &[u8]) -> Result<ClassicZipDirectory, String> {
    const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
    const ZIP64_LOCATOR_SIGNATURE: &[u8; 4] = b"PK\x06\x07";
    const EOCD_LENGTH: usize = 22;
    let search_start = package
        .len()
        .saturating_sub(EOCD_LENGTH + u16::MAX as usize);
    let Some(search_end) = package.len().checked_sub(EOCD_LENGTH) else {
        return Err(
            "factory package is not a valid ZIP archive under the canonical classic contract: missing end record"
                .into(),
        );
    };
    for offset in (search_start..=search_end).rev() {
        if package.get(offset..offset + 4) != Some(EOCD_SIGNATURE) {
            continue;
        }

        let Some(comment_length) = zip_u16(package, offset + 20) else {
            continue;
        };
        if offset
            .checked_add(EOCD_LENGTH)
            .and_then(|end| end.checked_add(comment_length as usize))
            != Some(package.len())
        {
            continue;
        }

        let (Some(disk), Some(central_disk), Some(disk_entries), Some(entries)) = (
            zip_u16(package, offset + 4),
            zip_u16(package, offset + 6),
            zip_u16(package, offset + 8),
            zip_u16(package, offset + 10),
        ) else {
            continue;
        };
        let (Some(central_size), Some(central_offset)) =
            (zip_u32(package, offset + 12), zip_u32(package, offset + 16))
        else {
            continue;
        };
        let has_zip64_locator =
            offset >= 20 && package.get(offset - 20..offset - 16) == Some(ZIP64_LOCATOR_SIGNATURE);
        if disk == u16::MAX
            || central_disk == u16::MAX
            || disk_entries == u16::MAX
            || entries == u16::MAX
            || central_size == u32::MAX
            || central_offset == u32::MAX
            || has_zip64_locator
        {
            return Err("factory package ZIP64 archives are not supported".into());
        }
        if disk != 0 || central_disk != 0 || disk_entries != entries {
            return Err("factory package must be a single-disk classic ZIP archive".into());
        }
        let central_offset = central_offset as usize;
        let central_size = central_size as usize;
        let Some(central_end) = central_offset.checked_add(central_size) else {
            continue;
        };
        if central_end != offset {
            continue;
        }
        if entries as usize > MAX_ARCHIVE_ENTRIES {
            return Ok(ClassicZipDirectory {
                entries: entries as usize,
                offset: central_offset,
            });
        }
        validate_classic_zip_structure(package, central_offset, central_end, entries as usize)?;
        return Ok(ClassicZipDirectory {
            entries: entries as usize,
            offset: central_offset,
        });
    }
    Err(
        "factory package is not a valid ZIP archive under the canonical classic contract: missing end record"
            .into(),
    )
}

fn validate_classic_zip_structure(
    package: &[u8],
    central_offset: usize,
    central_end: usize,
    entries: usize,
) -> Result<(), String> {
    const CENTRAL_SIGNATURE: &[u8; 4] = b"PK\x01\x02";
    const LOCAL_SIGNATURE: &[u8; 4] = b"PK\x03\x04";
    const CENTRAL_HEADER_LENGTH: usize = 46;
    const LOCAL_HEADER_LENGTH: usize = 30;
    const ZIP_FLAG_ENCRYPTED: u16 = 1 << 0;
    const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 1 << 3;
    const UNIX_SYSTEM: u8 = 3;
    const UNIX_FILE_TYPE_MASK: u32 = 0o170000;
    const UNIX_REGULAR_FILE: u32 = 0o100000;
    const DOS_DIRECTORY_ATTRIBUTE: u32 = 0x10;

    let mut central_cursor = central_offset;
    let mut local_spans = Vec::with_capacity(entries);
    let mut declared_artifact_bytes = 0_u64;
    let mut saw_manifest = false;
    for _ in 0..entries {
        let fixed_end = central_cursor
            .checked_add(CENTRAL_HEADER_LENGTH)
            .ok_or_else(|| "factory package central-directory offset overflow".to_string())?;
        if fixed_end > central_end
            || package.get(central_cursor..central_cursor + 4) != Some(CENTRAL_SIGNATURE)
        {
            return Err("factory package has an invalid central-directory entry".into());
        }

        let made_by_system = *package
            .get(central_cursor + 5)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let flags = zip_u16(package, central_cursor + 8)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let method = zip_u16(package, central_cursor + 10)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let crc = zip_u32(package, central_cursor + 16)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let compressed_size = zip_u32(package, central_cursor + 20)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let uncompressed_size = zip_u32(package, central_cursor + 24)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let name_length = zip_u16(package, central_cursor + 28)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?
            as usize;
        let extra_length = zip_u16(package, central_cursor + 30)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?
            as usize;
        let comment_length = zip_u16(package, central_cursor + 32)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?
            as usize;
        let disk_start = zip_u16(package, central_cursor + 34)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let external_attributes = zip_u32(package, central_cursor + 38)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;
        let local_offset = zip_u32(package, central_cursor + 42)
            .ok_or_else(|| "factory package has a truncated central-directory entry".to_string())?;

        if compressed_size == u32::MAX
            || uncompressed_size == u32::MAX
            || local_offset == u32::MAX
            || disk_start == u16::MAX
        {
            return Err("factory package ZIP64 archives are not supported".into());
        }
        if flags & ZIP_FLAG_ENCRYPTED != 0 {
            return Err("factory package encrypted ZIP entries are not supported".into());
        }
        // The canonical pcbex writer uses seekable output and emits neither
        // data descriptors nor extra fields. Rejecting them keeps the raw and
        // library ZIP views identical instead of accepting alternate metadata.
        if flags & ZIP_FLAG_DATA_DESCRIPTOR != 0 {
            return Err("factory package ZIP data descriptors are not supported".into());
        }
        if disk_start != 0 {
            return Err("factory package must be a single-disk classic ZIP archive".into());
        }
        if extra_length != 0 {
            return Err("factory package central ZIP extra fields are not supported".into());
        }
        let unix_mode = external_attributes >> 16;
        let unix_file_type = unix_mode & UNIX_FILE_TYPE_MASK;
        if external_attributes & DOS_DIRECTORY_ATTRIBUTE != 0
            || (unix_file_type != UNIX_REGULAR_FILE
                && (made_by_system == UNIX_SYSTEM || unix_mode != 0))
        {
            return Err("factory package ZIP entries must be regular files".into());
        }

        let central_name_start = fixed_end;
        let central_name_end = central_name_start
            .checked_add(name_length)
            .ok_or_else(|| "factory package central-directory name overflow".to_string())?;
        let next_central = central_name_end
            .checked_add(extra_length)
            .and_then(|end| end.checked_add(comment_length))
            .ok_or_else(|| "factory package central-directory entry overflow".to_string())?;
        if next_central > central_end {
            return Err("factory package has a truncated central-directory entry".into());
        }
        let central_name = package
            .get(central_name_start..central_name_end)
            .ok_or_else(|| "factory package has a truncated central-directory name".to_string())?;

        let local_offset = local_offset as usize;
        let local_fixed_end = local_offset
            .checked_add(LOCAL_HEADER_LENGTH)
            .ok_or_else(|| "factory package local-header offset overflow".to_string())?;
        if local_fixed_end > central_offset
            || package.get(local_offset..local_offset + 4) != Some(LOCAL_SIGNATURE)
        {
            return Err(
                "factory package central directory references an invalid local header".into(),
            );
        }
        let local_flags = zip_u16(package, local_offset + 6)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?;
        let local_method = zip_u16(package, local_offset + 8)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?;
        let local_crc = zip_u32(package, local_offset + 14)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?;
        let local_compressed_size = zip_u32(package, local_offset + 18)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?;
        let local_uncompressed_size = zip_u32(package, local_offset + 22)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?;
        let local_name_length = zip_u16(package, local_offset + 26)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?
            as usize;
        let local_extra_length = zip_u16(package, local_offset + 28)
            .ok_or_else(|| "factory package has a truncated local header".to_string())?
            as usize;
        if local_extra_length != 0 {
            return Err("factory package local ZIP extra fields are not supported".into());
        }
        if local_flags != flags
            || local_method != method
            || local_crc != crc
            || local_compressed_size != compressed_size
            || local_uncompressed_size != uncompressed_size
        {
            return Err("factory package local and central ZIP metadata differ".into());
        }

        let local_name_start = local_fixed_end;
        let local_name_end = local_name_start
            .checked_add(local_name_length)
            .ok_or_else(|| "factory package local-header name overflow".to_string())?;
        let local_data_start = local_name_end
            .checked_add(local_extra_length)
            .ok_or_else(|| "factory package local-header entry overflow".to_string())?;
        let local_end = local_data_start
            .checked_add(compressed_size as usize)
            .ok_or_else(|| "factory package local-entry size overflow".to_string())?;
        if local_end > central_offset {
            return Err("factory package local ZIP entry overlaps the central directory".into());
        }
        let local_name = package
            .get(local_name_start..local_name_end)
            .ok_or_else(|| "factory package has a truncated local-header name".to_string())?;
        if local_name != central_name {
            return Err("factory package local and central ZIP entry names differ".into());
        }
        if central_name == b"manifest.json" {
            if saw_manifest {
                return Err("factory package contains duplicate ZIP entry manifest.json".into());
            }
            saw_manifest = true;
            if u64::from(uncompressed_size) > MAX_MANIFEST_BYTES {
                return Err(format!(
                    "factory package manifest.json must contain 1 to {MAX_MANIFEST_BYTES} bytes"
                ));
            }
        } else {
            declared_artifact_bytes = declared_artifact_bytes
                .checked_add(u64::from(uncompressed_size))
                .ok_or_else(|| "factory package ZIP entry size overflow".to_string())?;
            if declared_artifact_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
                return Err(format!(
                    "factory package decompressed artifact bytes exceed {MAX_ARCHIVE_UNCOMPRESSED_BYTES}"
                ));
            }
        }
        let compressed_data = package
            .get(local_data_start..local_end)
            .ok_or_else(|| "factory package has truncated local ZIP entry data".to_string())?;
        validate_classic_zip_entry_stream(method, compressed_data, uncompressed_size)?;
        local_spans.push((local_offset, local_end));
        central_cursor = next_central;
    }
    if central_cursor != central_end {
        return Err("factory package central-directory size does not match its entries".into());
    }

    local_spans.sort_unstable_by_key(|(start, _)| *start);
    let mut local_cursor = 0_usize;
    for (start, end) in local_spans {
        if start != local_cursor {
            return Err("factory package contains unlisted or overlapping local ZIP data".into());
        }
        local_cursor = end;
    }
    if local_cursor != central_offset {
        return Err("factory package contains unlisted local ZIP data".into());
    }
    Ok(())
}

fn validate_classic_zip_entry_stream(
    method: u16,
    compressed_data: &[u8],
    uncompressed_size: u32,
) -> Result<(), String> {
    const STORED_METHOD: u16 = 0;
    const DEFLATED_METHOD: u16 = 8;

    if u64::from(uncompressed_size) > MAX_PACKAGE_BYTES {
        return Err("factory package ZIP entry exceeds size limit".into());
    }

    match method {
        STORED_METHOD => {
            if compressed_data.len() as u64 != u64::from(uncompressed_size) {
                return Err(
                    "factory package stored ZIP entry sizes do not match its byte stream".into(),
                );
            }
            Ok(())
        }
        DEFLATED_METHOD => {
            let mut decompressor = Decompress::new(false);
            let mut output = [0_u8; 64 * 1024];
            let declared_output = u64::from(uncompressed_size);

            loop {
                let before_input = decompressor.total_in();
                let before_output = decompressor.total_out();
                let input_start = usize::try_from(before_input).map_err(|_| {
                    "factory package deflated ZIP entry input offset overflow".to_string()
                })?;
                let remaining_input = compressed_data.get(input_start..).ok_or_else(|| {
                    "factory package deflated ZIP entry consumed beyond its declared compressed size"
                        .to_string()
                })?;
                // Permit one byte beyond the declaration so an understated
                // uncompressed size is detected without expanding attacker-
                // controlled data beyond that bound.
                let output_limit = declared_output
                    .saturating_sub(before_output)
                    .saturating_add(1)
                    .min(output.len() as u64) as usize;
                let status = decompressor
                    .decompress(
                        remaining_input,
                        &mut output[..output_limit],
                        FlushDecompress::None,
                    )
                    .map_err(|error| {
                        format!("factory package has an invalid deflated ZIP entry: {error}")
                    })?;
                let after_input = decompressor.total_in();
                let after_output = decompressor.total_out();
                if after_output > declared_output {
                    return Err(
                        "factory package deflated ZIP entry expands beyond its declared uncompressed size"
                            .into(),
                    );
                }

                if status == Status::StreamEnd {
                    if after_input != compressed_data.len() as u64 {
                        return Err(
                            "factory package deflated ZIP entry does not consume exactly its declared compressed size"
                                .into(),
                        );
                    }
                    if after_output != declared_output {
                        return Err(
                            "factory package deflated ZIP entry size does not match its byte stream"
                                .into(),
                        );
                    }
                    return Ok(());
                }

                if after_input == before_input && after_output == before_output {
                    return Err(
                        "factory package deflated ZIP entry does not terminate within its declared compressed size"
                            .into(),
                    );
                }
            }
        }
        _ => Err(format!(
            "factory package ZIP compression method {method} is not supported"
        )),
    }
}

fn zip_u16(package: &[u8], offset: usize) -> Option<u16> {
    package
        .get(offset..offset.checked_add(2)?)?
        .try_into()
        .ok()
        .map(u16::from_le_bytes)
}

fn zip_u32(package: &[u8], offset: usize) -> Option<u32> {
    package
        .get(offset..offset.checked_add(4)?)?
        .try_into()
        .ok()
        .map(u32::from_le_bytes)
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
    if descriptor.path.eq_ignore_ascii_case("manifest.json")
        || descriptor.path.eq_ignore_ascii_case("manufacturing.zip")
    {
        return Err(format!(
            "factory package {kind} descriptor must not reference a reserved archive name"
        ));
    }
    if descriptor.bytes == 0 || descriptor.bytes > MAX_PACKAGE_BYTES {
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
    validate_manufacturing_basename(
        path,
        ManufacturingLimits::production().max_name_bytes,
        "factory package path",
    )
    .is_ok()
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

fn read_validated_zip_entry(
    package: &[u8],
    name: &str,
    maximum_bytes: u64,
) -> Result<Vec<u8>, String> {
    let mut archive = ZipArchive::new(Cursor::new(package))
        .map_err(|error| format!("factory package is not a valid ZIP archive: {error}"))?;
    let entry = archive
        .by_name(name)
        .map_err(|_| format!("factory package must contain {name}"))?;
    let mut bytes = Vec::new();
    entry
        .take(maximum_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading factory package ZIP entry {name}: {error}"))?;
    if bytes.len() as u64 > maximum_bytes {
        return Err(format!(
            "factory package ZIP entry {name} exceeds size limit"
        ));
    }
    Ok(bytes)
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
            validate_factory_text(status, "factory status", MAX_FACTORY_STATUS_CHARS, true)?;
            status.to_string()
        }
        None => "unknown".to_string(),
    };
    let accepted = match object.get("accepted") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| "factory accepted must be a boolean".to_string())?,
        None => false,
    };
    let dfm_passed = match object.get("dfm_passed") {
        Some(value) if value.is_null() => None,
        Some(value) => Some(
            value
                .as_bool()
                .ok_or_else(|| "factory dfm_passed must be a boolean or null".to_string())?,
        ),
        // Nested provider-specific DFM objects remain available in the raw
        // response, but they cannot establish the normalized gate because
        // their finding shape is not part of the closed v1 contract.
        None => None,
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
        if values.len() > MAX_FACTORY_FINDINGS {
            return Err(format!(
                "factory findings must contain at most {MAX_FACTORY_FINDINGS} entries"
            ));
        }
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
                    validate_factory_text(
                        message,
                        "factory finding message",
                        MAX_FACTORY_FINDING_MESSAGE_CHARS,
                        true,
                    )?;
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
                    if !code.is_empty() {
                        validate_factory_text(
                            code,
                            "factory finding code",
                            MAX_FACTORY_FINDING_CODE_CHARS,
                            true,
                        )?;
                    }
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
                        validate_factory_text(
                            &severity,
                            "factory finding severity",
                            MAX_FACTORY_SEVERITY_CHARS,
                            true,
                        )?;
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

/// Validate a factory receipt without contacting the endpoint.
///
/// The receipt is an evidence artifact, so this check verifies its closed
/// shape, internal consistency, and endpoint policy.  Whether the factory
/// outcome is acceptable remains the responsibility of
/// [`factory_feedback_passed`].
pub fn validate_factory_submission_receipt(
    receipt: &FactorySubmissionReceipt,
    allow_http_loopback: bool,
) -> Result<(), String> {
    if receipt.schema_version != 1 {
        return Err("factory receipt schema_version must be 1".into());
    }

    validate_factory_text(
        &receipt.adapter,
        "factory receipt adapter",
        MAX_FACTORY_ADAPTER_CHARS,
        true,
    )?;
    if receipt.adapter != receipt.provider.adapter_name() {
        return Err("factory receipt adapter does not match its provider".into());
    }
    validate_factory_text(
        &receipt.endpoint,
        "factory receipt endpoint",
        MAX_FACTORY_ENDPOINT_CHARS,
        true,
    )?;
    validate_endpoint(&receipt.endpoint, allow_http_loopback)?;
    validate_factory_text(
        &receipt.status,
        "factory receipt status",
        MAX_FACTORY_STATUS_CHARS,
        true,
    )?;

    for (label, digest) in [
        ("package_sha256", &receipt.package_sha256),
        ("request_sha256", &receipt.request_sha256),
        ("response_sha256", &receipt.response_sha256),
    ] {
        if !is_sha256(digest) {
            return Err(format!(
                "factory receipt {label} is not a lowercase SHA-256"
            ));
        }
    }
    if receipt.package_sha256 != receipt.request_sha256 {
        return Err("factory receipt package_sha256 and request_sha256 differ".into());
    }
    if receipt.package_bytes == 0 || receipt.package_bytes > MAX_PACKAGE_BYTES {
        return Err(format!(
            "factory receipt package_bytes must contain 1 to {MAX_PACKAGE_BYTES} bytes"
        ));
    }
    if receipt.response_bytes == 0 || receipt.response_bytes > MAX_RESPONSE_BYTES {
        return Err(format!(
            "factory receipt response_bytes must contain 1 to {MAX_RESPONSE_BYTES} bytes"
        ));
    }
    if !(200..=599).contains(&receipt.http_status) {
        return Err("factory receipt http_status must be between 200 and 599".into());
    }

    if receipt.findings.len() > MAX_FACTORY_FINDINGS {
        return Err(format!(
            "factory receipt findings must contain at most {MAX_FACTORY_FINDINGS} entries"
        ));
    }
    for finding in &receipt.findings {
        if let Some(code) = finding.code.as_deref() {
            validate_factory_text(
                code,
                "factory receipt finding code",
                MAX_FACTORY_FINDING_CODE_CHARS,
                true,
            )?;
        }
        validate_factory_text(
            &finding.message,
            "factory receipt finding message",
            MAX_FACTORY_FINDING_MESSAGE_CHARS,
            true,
        )?;
        let canonical_severity = finding.severity.trim().to_ascii_lowercase();
        if canonical_severity.is_empty()
            || canonical_severity != finding.severity
            || canonical_severity.chars().count() > MAX_FACTORY_SEVERITY_CHARS
            || canonical_severity.contains('\0')
        {
            return Err(
                "factory receipt finding severity must be non-empty lowercase canonical text"
                    .into(),
            );
        }
    }

    if !receipt.response.is_object() {
        return Err("factory receipt response must be a JSON object".into());
    }
    let normalized = normalize_response(&receipt.response)?;
    if receipt.status != normalized.status {
        return Err("factory receipt status does not match normalized response".into());
    }
    if receipt.accepted != normalized.accepted {
        return Err("factory receipt accepted does not match normalized response".into());
    }
    if receipt.dfm_passed != normalized.dfm_passed {
        return Err("factory receipt dfm_passed does not match normalized response".into());
    }
    if receipt.quote != normalized.quote {
        return Err("factory receipt quote does not match normalized response".into());
    }
    if receipt.findings != normalized.findings {
        return Err("factory receipt findings do not match normalized response".into());
    }
    Ok(())
}

fn response_contains_bearer_token(response: &[u8], value: &Value, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    let token_bytes = token.as_bytes();
    response
        .windows(token_bytes.len())
        .any(|window| window == token_bytes)
        || json_contains_bearer_token(value, token)
}

fn json_contains_bearer_token(value: &Value, token: &str) -> bool {
    match value {
        Value::String(value) => value.contains(token),
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_bearer_token(value, token)),
        Value::Object(values) => values
            .iter()
            .any(|(key, value)| key.contains(token) || json_contains_bearer_token(value, token)),
        Value::Null | Value::Bool(_) | Value::Number(_) => false,
    }
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
        sync::{
            Arc, Mutex,
            atomic::{AtomicU64, Ordering},
        },
        thread::{self, JoinHandle},
    };
    use tempfile::tempdir;
    use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

    type ReceivedRequests = Arc<Mutex<Vec<Vec<u8>>>>;

    struct TestManufacturingCsv {
        bom: Vec<u8>,
        cpl: Vec<u8>,
        bom_quantity: u64,
        placement_rows: u64,
    }

    impl TestManufacturingCsv {
        fn empty() -> Self {
            Self {
                bom: b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n".to_vec(),
                cpl: b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n".to_vec(),
                bom_quantity: 0,
                placement_rows: 0,
            }
        }
    }

    fn manufacturing_package() -> Vec<u8> {
        manufacturing_package_with_front_copper(b"front-copper".to_vec(), CompressionMethod::Stored)
    }

    fn manufacturing_package_with_front_copper(
        front_copper: Vec<u8>,
        compression_method: CompressionMethod,
    ) -> Vec<u8> {
        manufacturing_package_with_profile(front_copper, compression_method, 1, None)
    }

    fn manufacturing_package_with_profile(
        front_copper: Vec<u8>,
        compression_method: CompressionMethod,
        schema_version: u32,
        physical_profile: Option<&PhysicalProfileBinding>,
    ) -> Vec<u8> {
        manufacturing_package_with_profile_and_csv(
            front_copper,
            compression_method,
            schema_version,
            physical_profile,
            TestManufacturingCsv::empty(),
        )
    }

    fn manufacturing_package_with_csv(
        bom: Vec<u8>,
        cpl: Vec<u8>,
        bom_quantity: u64,
        placement_rows: u64,
    ) -> Vec<u8> {
        manufacturing_package_with_profile_and_csv(
            b"front-copper".to_vec(),
            CompressionMethod::Stored,
            1,
            None,
            TestManufacturingCsv {
                bom,
                cpl,
                bom_quantity,
                placement_rows,
            },
        )
    }

    fn manufacturing_package_with_profile_and_csv(
        front_copper: Vec<u8>,
        compression_method: CompressionMethod,
        schema_version: u32,
        physical_profile: Option<&PhysicalProfileBinding>,
        csv: TestManufacturingCsv,
    ) -> Vec<u8> {
        let TestManufacturingCsv {
            bom,
            cpl,
            bom_quantity,
            placement_rows,
        } = csv;
        let board = b"board-bytes";
        let job = serde_json::to_vec(&json!({
            "GeneralSpecs": {"LayerNumber": 2},
            "FilesAttributes": [
                {"Path": "board-F_Cu.gtl", "FileFunction": "Copper,L1,Top"},
                {"Path": "board-B_Cu.gbl", "FileFunction": "Copper,L2,Bot"},
                {"Path": "board-f_mask.gts", "FileFunction": "SolderMask,Top"},
                {"Path": "board-b_mask.gbs", "FileFunction": "SolderMask,Bot"},
                {"Path": "board-f_silkscreen.gto", "FileFunction": "Legend,Top"},
                {"Path": "board-b_silkscreen.gbo", "FileFunction": "Legend,Bot"},
                {"Path": "board-Edge_Cuts.gm1", "FileFunction": "Profile"}
            ]
        }))
        .unwrap();
        let artifacts = vec![
            ("board-F_Cu.gtl", front_copper),
            ("board-B_Cu.gbl", b"back-copper".to_vec()),
            ("board-f_mask.gts", b"front-mask".to_vec()),
            ("board-b_mask.gbs", b"back-mask".to_vec()),
            ("board-f_silkscreen.gto", b"front-legend".to_vec()),
            ("board-b_silkscreen.gbo", b"back-legend".to_vec()),
            ("board-Edge_Cuts.gm1", b"profile".to_vec()),
            ("board-job.gbrjob", job),
            ("board.drl", b"drill".to_vec()),
            ("drc.rpt", b"DRC clean".to_vec()),
            ("bom.csv", bom),
            ("cpl.csv", cpl),
        ];
        let mut manifest = json!({
            "schema_version": schema_version,
            "engine": "pcbex",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "tools": {"kicad_cli": "10.0.5", "kicad_cli_about_sha256": "a".repeat(64)},
            "input": {
                "path": "board.kicad_pcb",
                "bytes": board.len(),
                "sha256": sha256(board)
            },
            "project_inputs": [],
            "parts": {"total": bom_quantity.max(placement_rows), "bom": bom_quantity, "placement": placement_rows, "dnp": 0},
            "artifacts": artifacts.iter().map(|(path, bytes)| json!({
                "path": path,
                "bytes": bytes.len(),
                "sha256": sha256(bytes)
            })).collect::<Vec<_>>(),
            "archive": "manufacturing.zip"
        });
        if let Some(binding) = physical_profile {
            manifest["physical_profile"] = serde_json::to_value(binding).unwrap();
        }
        let manifest_bytes = serde_json::to_vec(&manifest).unwrap();
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(compression_method);
        for (path, bytes) in artifacts {
            writer.start_file(path, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.start_file("manifest.json", options).unwrap();
        writer.write_all(&manifest_bytes).unwrap();
        writer.finish().unwrap().into_inner()
    }

    fn physical_profile_binding() -> PhysicalProfileBinding {
        PhysicalProfileBinding {
            schema_version: 1,
            id: "fixture-v1".into(),
            revision: 1,
            canonical_sha256: "b".repeat(64),
            source: crate::physical_profile::PhysicalProfileSource {
                path: "profile.json".into(),
                bytes: 1,
                sha256: "c".repeat(64),
            },
        }
    }

    fn dfm_profile_binding() -> DfmProfileBinding {
        crate::dfm_profile_binding::builtin_dfm_profile_binding(
            &pcbex_core::dfm_profile("jlcpcb-2layer").unwrap(),
        )
        .unwrap()
    }

    fn manufacturing_package_with_dfm_profile() -> Vec<u8> {
        rewrite_manifest(manufacturing_package(), |manifest| {
            let binding = dfm_profile_binding();
            manifest["schema_version"] = json!(3);
            manifest["dfm_profile"] = serde_json::to_value(binding).unwrap();
        })
    }

    fn rewrite_manifest(package: Vec<u8>, edit: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut archive = ZipArchive::new(Cursor::new(package)).unwrap();
        let mut entries = Vec::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            let name = entry.name().to_string();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            entries.push((name, bytes));
        }
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        let mut edit = Some(edit);
        for (name, mut bytes) in entries {
            if name == "manifest.json" {
                let mut manifest: Value = serde_json::from_slice(&bytes).unwrap();
                edit.take().expect("manifest is present")(&mut manifest);
                bytes = serde_json::to_vec(&manifest).unwrap();
            }
            writer.start_file(name, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn manifest_bytes(package: &[u8]) -> Vec<u8> {
        let mut archive = ZipArchive::new(Cursor::new(package)).unwrap();
        let mut entry = archive.by_name("manifest.json").unwrap();
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn replace_manifest_bytes(package: Vec<u8>, replacement: &[u8]) -> Vec<u8> {
        let mut archive = ZipArchive::new(Cursor::new(package)).unwrap();
        let mut entries = Vec::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            let name = entry.name().to_string();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            entries.push((name, bytes));
        }
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        for (name, bytes) in entries {
            writer.start_file(&name, options).unwrap();
            if name == "manifest.json" {
                writer.write_all(replacement).unwrap();
            } else {
                writer.write_all(&bytes).unwrap();
            }
        }
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

    fn spawn_http_sequence(bodies: Vec<Vec<u8>>) -> (String, ReceivedRequests, JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/quote", listener.local_addr().unwrap());
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_by_server = Arc::clone(&received);
        let handle = thread::spawn(move || {
            for body in bodies {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "factory client did not make the expected request"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accepting factory request: {error}"),
                    }
                };
                received_by_server
                    .lock()
                    .unwrap()
                    .push(read_http_request(&mut stream));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&body);
            }
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

    fn receipt_for_response(response: Value) -> FactorySubmissionReceipt {
        let normalized = normalize_response(&response).unwrap();
        FactorySubmissionReceipt {
            schema_version: 1,
            adapter: FactoryProvider::Generic.adapter_name().into(),
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
            response,
        }
    }

    fn unique_env_name(prefix: &str) -> String {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        format!(
            "{prefix}_{}_{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )
    }

    #[cfg(unix)]
    fn write_repair_script(
        directory: &Path,
        name: impl AsRef<std::ffi::OsStr>,
        body: &str,
    ) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = directory.join(Path::new(name.as_ref()));
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[test]
    fn normalizes_provider_feedback_and_gate() {
        let value = json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
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
            !normalize_response(&json!({"status": "quoted"}))
                .unwrap()
                .accepted
        );
        assert!(
            normalize_response(&json!({
                "dfm_passed": true,
                "dfm": {"passed": true}
            }))
            .is_err()
        );
        assert_eq!(
            normalize_response(&json!({
                "accepted": true,
                "dfm": {
                    "passed": true,
                    "findings": [{"severity": "error", "message": "nested error"}]
                }
            }))
            .unwrap()
            .dfm_passed,
            None
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
    fn validates_a_structurally_consistent_factory_receipt_offline() {
        let response = json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "quote": {"total": 12.5, "currency": "USD"},
            "dfm_findings": [
                {"code": "silk", "severity": "warning", "message": "overlap"},
                {"code": "trace", "severity": "info", "message": "long"}
            ]
        });
        let receipt = receipt_for_response(response);
        assert!(validate_factory_submission_receipt(&receipt, false).is_ok());
        assert!(factory_feedback_passed(&receipt));
    }

    #[test]
    fn rejects_receipt_adapter_digest_and_normalized_field_mismatches() {
        let response = json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "dfm_findings": []
        });
        let receipt = receipt_for_response(response);

        let mut adapter = receipt.clone();
        adapter.adapter = FactoryProvider::Pcbway.adapter_name().into();
        assert!(
            validate_factory_submission_receipt(&adapter, false)
                .unwrap_err()
                .contains("adapter")
        );

        let mut digest = receipt.clone();
        digest.request_sha256 = "c".repeat(64);
        assert!(
            validate_factory_submission_receipt(&digest, false)
                .unwrap_err()
                .contains("package_sha256 and request_sha256")
        );

        let mut status = receipt.clone();
        status.status = "accepted".into();
        assert!(
            validate_factory_submission_receipt(&status, false)
                .unwrap_err()
                .contains("status")
        );

        let mut findings = receipt;
        findings.findings.push(FactoryDfmFinding {
            code: None,
            severity: "info".into(),
            message: "unexpected".into(),
        });
        assert!(
            validate_factory_submission_receipt(&findings, false)
                .unwrap_err()
                .contains("findings")
        );
    }

    #[test]
    fn enforces_receipt_https_policy_and_keeps_unknown_severity_fail_closed() {
        let mut https = receipt_for_response(json!({
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }));
        https.endpoint = "http://127.0.0.1:8080/quote".into();
        assert!(validate_factory_submission_receipt(&https, false).is_err());
        assert!(validate_factory_submission_receipt(&https, true).is_ok());

        let unknown = receipt_for_response(json!({
            "accepted": true,
            "dfm_passed": true,
            "findings": [{"severity": "vendor-specific", "message": "opaque"}]
        }));
        assert!(validate_factory_submission_receipt(&unknown, false).is_ok());
        assert!(!factory_feedback_passed(&unknown));
    }

    #[test]
    fn bounds_receipt_findings_and_finding_text() {
        let mut long_message = receipt_for_response(json!({
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }));
        long_message.findings.push(FactoryDfmFinding {
            code: Some("code".into()),
            severity: "info".into(),
            message: "x".repeat(MAX_FACTORY_FINDING_MESSAGE_CHARS + 1),
        });
        assert!(validate_factory_submission_receipt(&long_message, false).is_err());

        let mut too_many = receipt_for_response(json!({
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }));
        too_many.findings = vec![
            FactoryDfmFinding {
                code: None,
                severity: "info".into(),
                message: "finding".into(),
            };
            MAX_FACTORY_FINDINGS + 1
        ];
        assert!(validate_factory_submission_receipt(&too_many, false).is_err());
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
        assert!(windows_environment_name_matches("temp", "TEMP"));
        assert!(windows_environment_name_matches("SystemRoot", "SYSTEMROOT"));
        assert!(!windows_environment_name_matches(
            "PCBEX_FACTORY_TOKEN",
            "TEMP"
        ));
    }

    #[test]
    fn rejects_unsafe_archive_basenames_at_shared_name_limit() {
        let name_limit = ManufacturingLimits::production().max_name_bytes;
        assert!(is_safe_manifest_path("board-F_Cu.gtl"));
        assert!(!is_safe_manifest_path("board:Cu.gtl"));
        assert!(!is_safe_manifest_path("board\nCu.gtl"));
        assert!(!is_safe_manifest_path("CON.gtl"));
        assert!(!is_safe_manifest_path("board.gtl."));
        assert!(!is_safe_manifest_path("board.gtl "));
        assert!(!is_safe_manifest_path(&"x".repeat(name_limit + 1)));
        assert!(is_safe_manifest_path(&"x".repeat(name_limit)));
    }

    #[test]
    fn caps_total_uncompressed_archive_entries() {
        let mut total = MAX_ARCHIVE_UNCOMPRESSED_BYTES - 1;
        assert!(
            add_archive_size_with_limit(
                &mut total,
                2,
                "large.gbr",
                MAX_ARCHIVE_UNCOMPRESSED_BYTES,
            )
            .is_err()
        );
        let mut total = u64::MAX;
        assert!(
            add_archive_size_with_limit(
                &mut total,
                1,
                "overflow.gbr",
                MAX_ARCHIVE_UNCOMPRESSED_BYTES,
            )
            .is_err()
        );

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("duplicate.txt", options).unwrap();
        writer.write_all(b"one").unwrap();
        let _ = writer.finish().unwrap().into_inner();
    }

    #[test]
    fn rejects_zip64_eocd_sentinels_and_locator_during_bounded_precheck() {
        const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
        let package = manufacturing_package();
        let eocd = package
            .windows(EOCD_SIGNATURE.len())
            .rposition(|window| window == EOCD_SIGNATURE)
            .unwrap();

        for (field_offset, width) in [(4, 2), (6, 2), (8, 2), (10, 2), (12, 4), (16, 4)] {
            let mut zip64 = package.clone();
            zip64[eocd + field_offset..eocd + field_offset + width].fill(0xff);
            let error = validate_manufacturing_package(&zip64).unwrap_err();
            assert!(
                error.contains("ZIP64 archives are not supported"),
                "{error}"
            );
        }

        let mut zip64_locator = package;
        zip64_locator[eocd - 20..eocd - 16].copy_from_slice(b"PK\x06\x07");
        let error = validate_manufacturing_package(&zip64_locator).unwrap_err();
        assert!(
            error.contains("ZIP64 archives are not supported"),
            "{error}"
        );
    }

    #[test]
    fn rejects_inconsistent_or_unlisted_raw_zip_records() {
        const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
        let package = manufacturing_package();
        validate_manufacturing_package(&package).unwrap();
        let eocd = package
            .windows(EOCD_SIGNATURE.len())
            .rposition(|window| window == EOCD_SIGNATURE)
            .unwrap();
        let central_offset = zip_u32(&package, eocd + 16).unwrap() as usize;

        let (local_offset, local_name_start) = {
            let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
            let entry = archive.by_index(0).unwrap();
            let local_offset = entry.header_start() as usize;
            (local_offset, local_offset + 30)
        };
        let mut mismatched_name = package.clone();
        mismatched_name[local_name_start] ^= 1;
        let error = validate_manufacturing_package(&mismatched_name).unwrap_err();
        assert!(error.contains("entry names differ"), "{error}");

        let mut undecodable_name = package.clone();
        undecodable_name[local_name_start] = 0xff;
        undecodable_name[central_offset + 46] = 0xff;
        let error = validate_manufacturing_package(&undecodable_name).unwrap_err();
        assert!(error.contains("raw and decoded names differ"), "{error}");

        let mut encrypted = package.clone();
        encrypted[central_offset + 8..central_offset + 10].copy_from_slice(&1_u16.to_le_bytes());
        encrypted[local_offset + 6..local_offset + 8].copy_from_slice(&1_u16.to_le_bytes());
        let error = validate_manufacturing_package(&encrypted).unwrap_err();
        assert!(error.contains("encrypted ZIP entries"), "{error}");

        let mut nonregular = package.clone();
        nonregular[central_offset + 5] = 3;
        nonregular[central_offset + 38..central_offset + 42]
            .copy_from_slice(&(0o120777_u32 << 16).to_le_bytes());
        let error = validate_manufacturing_package(&nonregular).unwrap_err();
        assert!(error.contains("must be regular files"), "{error}");

        let mut dos_nonregular = package.clone();
        dos_nonregular[central_offset + 5] = 0;
        dos_nonregular[central_offset + 38..central_offset + 42]
            .copy_from_slice(&(0o140777_u32 << 16).to_le_bytes());
        let error = validate_manufacturing_package(&dos_nonregular).unwrap_err();
        assert!(error.contains("must be regular files"), "{error}");

        let mut dos_directory = package.clone();
        dos_directory[central_offset + 5] = 0;
        dos_directory[central_offset + 38..central_offset + 42]
            .copy_from_slice(&0x10_u32.to_le_bytes());
        let error = validate_manufacturing_package(&dos_directory).unwrap_err();
        assert!(error.contains("must be regular files"), "{error}");

        let mut ambiguous_unix_mode = package.clone();
        ambiguous_unix_mode[central_offset + 5] = 3;
        ambiguous_unix_mode[central_offset + 38..central_offset + 42]
            .copy_from_slice(&(0o777_u32 << 16).to_le_bytes());
        let error = validate_manufacturing_package(&ambiguous_unix_mode).unwrap_err();
        assert!(error.contains("must be regular files"), "{error}");

        let mut missing_unix_file_type = package.clone();
        missing_unix_file_type[central_offset + 5] = 3;
        missing_unix_file_type[central_offset + 38..central_offset + 42]
            .copy_from_slice(&0_u32.to_le_bytes());
        let error = validate_manufacturing_package(&missing_unix_file_type).unwrap_err();
        assert!(error.contains("must be regular files"), "{error}");

        let central_name_length = zip_u16(&package, central_offset + 28).unwrap() as usize;
        let safe_name =
            package[central_offset + 46..central_offset + 46 + central_name_length].to_vec();
        let mut unsafe_name = vec![b'x'; central_name_length];
        unsafe_name[..3].copy_from_slice(b"../");
        let crc32 = |bytes: &[u8]| {
            let mut crc = u32::MAX;
            for byte in bytes {
                crc ^= *byte as u32;
                for _ in 0..8 {
                    crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
                }
            }
            !crc
        };
        let mut unicode_path_extra = Vec::new();
        unicode_path_extra.extend_from_slice(&0x7075_u16.to_le_bytes());
        unicode_path_extra.extend_from_slice(&(safe_name.len() as u16 + 5).to_le_bytes());
        unicode_path_extra.push(1);
        unicode_path_extra.extend_from_slice(&crc32(&unsafe_name).to_le_bytes());
        unicode_path_extra.extend_from_slice(&safe_name);
        let mut central_extra = package.clone();
        central_extra[local_name_start..local_name_start + central_name_length]
            .copy_from_slice(&unsafe_name);
        central_extra[central_offset + 46..central_offset + 46 + central_name_length]
            .copy_from_slice(&unsafe_name);
        let extra_start = central_offset + 46 + central_name_length;
        central_extra.splice(extra_start..extra_start, unicode_path_extra.iter().copied());
        central_extra[central_offset + 30..central_offset + 32]
            .copy_from_slice(&(unicode_path_extra.len() as u16).to_le_bytes());
        let shifted_eocd = eocd + unicode_path_extra.len();
        let shifted_central_size =
            zip_u32(&package, eocd + 12).unwrap() + unicode_path_extra.len() as u32;
        central_extra[shifted_eocd + 12..shifted_eocd + 16]
            .copy_from_slice(&shifted_central_size.to_le_bytes());
        let error = validate_manufacturing_package(&central_extra).unwrap_err();
        assert!(error.contains("central ZIP extra fields"), "{error}");

        let mut local_extra = package.clone();
        local_extra[local_offset + 28..local_offset + 30].copy_from_slice(&1_u16.to_le_bytes());
        let error = validate_manufacturing_package(&local_extra).unwrap_err();
        assert!(error.contains("local ZIP extra fields"), "{error}");

        let mut split_disk_entry = package.clone();
        split_disk_entry[central_offset + 34..central_offset + 36]
            .copy_from_slice(&1_u16.to_le_bytes());
        let error = validate_manufacturing_package(&split_disk_entry).unwrap_err();
        assert!(error.contains("single-disk classic ZIP"), "{error}");

        let orphan_name = b"orphan.txt";
        let mut orphan_prefix = Vec::new();
        orphan_prefix.extend_from_slice(b"PK\x03\x04");
        orphan_prefix.extend_from_slice(&20_u16.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u16.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u16.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u16.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u16.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u32.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u32.to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u32.to_le_bytes());
        orphan_prefix.extend_from_slice(&(orphan_name.len() as u16).to_le_bytes());
        orphan_prefix.extend_from_slice(&0_u16.to_le_bytes());
        orphan_prefix.extend_from_slice(orphan_name);
        let prefix_length = orphan_prefix.len();
        orphan_prefix.extend_from_slice(&package);
        let error = validate_manufacturing_package(&orphan_prefix).unwrap_err();
        assert!(
            error.contains("valid ZIP archive under the canonical classic contract"),
            "{error}"
        );

        let shifted_eocd = eocd + prefix_length;
        let shifted_central = central_offset + prefix_length;
        orphan_prefix[shifted_eocd + 16..shifted_eocd + 20]
            .copy_from_slice(&(shifted_central as u32).to_le_bytes());
        let entries = zip_u16(&orphan_prefix, shifted_eocd + 10).unwrap() as usize;
        let mut central_cursor = shifted_central;
        for _ in 0..entries {
            assert_eq!(
                orphan_prefix.get(central_cursor..central_cursor + 4),
                Some(b"PK\x01\x02".as_slice())
            );
            let shifted_local =
                zip_u32(&orphan_prefix, central_cursor + 42).unwrap() as usize + prefix_length;
            orphan_prefix[central_cursor + 42..central_cursor + 46]
                .copy_from_slice(&(shifted_local as u32).to_le_bytes());
            central_cursor += 46
                + zip_u16(&orphan_prefix, central_cursor + 28).unwrap() as usize
                + zip_u16(&orphan_prefix, central_cursor + 30).unwrap() as usize
                + zip_u16(&orphan_prefix, central_cursor + 32).unwrap() as usize;
        }
        let error = validate_manufacturing_package(&orphan_prefix).unwrap_err();
        assert!(
            error.contains("unlisted or overlapping local ZIP data"),
            "{error}"
        );
    }

    #[test]
    fn rejects_trailing_bytes_after_a_deflated_stream_end() {
        const EOCD_SIGNATURE: &[u8; 4] = b"PK\x05\x06";
        let mut package =
            manufacturing_package_with_front_copper(vec![b'x'; 4096], CompressionMethod::Deflated);
        validate_manufacturing_package(&package).unwrap();
        let eocd = package
            .windows(EOCD_SIGNATURE.len())
            .rposition(|window| window == EOCD_SIGNATURE)
            .unwrap();
        let central_offset = zip_u32(&package, eocd + 16).unwrap() as usize;
        let (local_header, data_end, central_header) = {
            let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
            let entry = archive.by_name("manifest.json").unwrap();
            assert_eq!(entry.compression(), CompressionMethod::Deflated);
            (
                entry.header_start() as usize,
                (entry.data_start().unwrap() + entry.compressed_size()) as usize,
                entry.central_header_start() as usize,
            )
        };
        assert_eq!(data_end, central_offset);

        let trailing = [0xde, 0xad, 0xbe, 0xef];
        package.splice(data_end..data_end, trailing);
        let compressed_size =
            zip_u32(&package, local_header + 18).unwrap() + u32::try_from(trailing.len()).unwrap();
        package[local_header + 18..local_header + 22]
            .copy_from_slice(&compressed_size.to_le_bytes());
        let shifted_central_header = central_header + trailing.len();
        package[shifted_central_header + 20..shifted_central_header + 24]
            .copy_from_slice(&compressed_size.to_le_bytes());
        let shifted_eocd = eocd + trailing.len();
        let shifted_central_offset = central_offset + trailing.len();
        package[shifted_eocd + 16..shifted_eocd + 20]
            .copy_from_slice(&(shifted_central_offset as u32).to_le_bytes());

        // The generic ZIP reader stops at the DEFLATE end marker and ignores
        // the opaque suffix inside the declared compressed range.
        let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
        let mut manifest = archive.by_name("manifest.json").unwrap();
        let mut decoded = Vec::new();
        manifest.read_to_end(&mut decoded).unwrap();
        assert!(!decoded.is_empty());

        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("does not consume exactly its declared compressed size"),
            "{error}"
        );
    }

    #[test]
    fn rejects_deflated_streams_that_exceed_declared_uncompressed_size() {
        let payload = vec![b'x'; 4096];
        let mut package =
            manufacturing_package_with_front_copper(payload.clone(), CompressionMethod::Deflated);
        let (local_header, central_header) = {
            let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
            let entry = archive.by_name("board-F_Cu.gtl").unwrap();
            (
                entry.header_start() as usize,
                entry.central_header_start() as usize,
            )
        };

        // Forge both ZIP headers to understate the uncompressed size while
        // retaining the compressed stream, CRC, and payload.
        package[local_header + 22..local_header + 26].copy_from_slice(&1_u32.to_le_bytes());
        package[central_header + 24..central_header + 28].copy_from_slice(&1_u32.to_le_bytes());

        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("expands beyond its declared uncompressed size"),
            "{error}"
        );
    }

    #[test]
    fn scans_workspace_at_exact_file_and_total_limits_then_rejects_plus_one() {
        let temporary = tempdir().unwrap();
        let file = temporary.path().join("candidate.bin");
        fs::write(&file, b"1234").unwrap();
        let mut limits = ManufacturingLimits::production();
        limits.max_file_bytes = 4;
        limits.max_total_bytes = 4;
        assert!(
            scan_manufacturing_workspace(temporary.path(), limits, "factory repair workspace")
                .is_ok()
        );

        fs::write(&file, b"12345").unwrap();
        let error =
            scan_manufacturing_workspace(temporary.path(), limits, "factory repair workspace")
                .unwrap_err();
        assert!(error.to_string().contains("limit"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn scans_workspace_rejects_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        let target = temporary.path().join("target.bin");
        let link = temporary.path().join("link.bin");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &link).unwrap();
        let error = scan_manufacturing_workspace(
            temporary.path(),
            ManufacturingLimits::production(),
            "factory repair workspace",
        )
        .unwrap_err();
        assert!(
            error.to_string().to_ascii_lowercase().contains("symlink"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn scans_workspace_rejects_nonregular_entries() {
        use std::os::unix::net::UnixListener;

        let temporary = tempdir().unwrap();
        let socket = temporary.path().join("candidate.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        let error = scan_manufacturing_workspace(
            temporary.path(),
            ManufacturingLimits::production(),
            "factory repair workspace",
        )
        .unwrap_err();
        assert!(
            error.to_string().to_ascii_lowercase().contains("regular"),
            "{error:#}"
        );
    }

    #[test]
    fn rejects_incomplete_manufacturing_artifact_and_layer_contracts() {
        let hash = "a".repeat(64);
        let mut artifacts = BTreeMap::from([
            ("bom.csv".to_string(), (1, hash.clone())),
            ("cpl.csv".to_string(), (1, hash.clone())),
            ("drc.rpt".to_string(), (1, hash.clone())),
            ("board.drl".to_string(), (1, hash.clone())),
            ("board-job.gbrjob".to_string(), (1, hash.clone())),
        ]);
        artifacts.remove("bom.csv");
        assert!(
            validate_required_manufacturing_artifacts(&artifacts)
                .unwrap_err()
                .contains("bom.csv")
        );
        artifacts.insert("bom.csv".to_string(), (1, hash.clone()));
        artifacts.insert("firmware.bin".to_string(), (1, hash.clone()));
        assert!(
            validate_required_manufacturing_artifacts(&artifacts)
                .unwrap_err()
                .contains("unsupported")
        );

        let empty = ManufacturingDescriptor {
            path: "bom.csv".into(),
            bytes: 0,
            sha256: hash.clone(),
        };
        assert!(validate_manifest_descriptor(&empty, "artifact").is_err());
        let reserved = ManufacturingDescriptor {
            path: "manifest.json".into(),
            bytes: 1,
            sha256: hash.clone(),
        };
        assert!(validate_manifest_descriptor(&reserved, "input").is_err());
        assert!(
            validate_manifest_path_domains(
                &BTreeSet::from(["bom.csv".to_string()]),
                &BTreeMap::from([("bom.csv".to_string(), (1, hash.clone()))]),
            )
            .unwrap_err()
            .contains("both provenance and an artifact")
        );

        let job = json!({
            "GeneralSpecs": {"LayerNumber": 4},
            "FilesAttributes": [
                {"Path": "board-F_Cu.gtl", "FileFunction": "Copper,L1,Top"},
                {"Path": "board-B_Cu.gbl", "FileFunction": "Copper,L4,Bot"},
                {"Path": "board-f_mask.gts", "FileFunction": "SolderMask,Top"},
                {"Path": "board-b_mask.gbs", "FileFunction": "SolderMask,Bot"},
                {"Path": "board-f_silkscreen.gto", "FileFunction": "Legend,Top"},
                {"Path": "board-b_silkscreen.gbo", "FileFunction": "Legend,Bot"},
                {"Path": "board-Edge_Cuts.gm1", "FileFunction": "Profile"}
            ]
        });
        let job_bytes = serde_json::to_vec(&job).unwrap();
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer.start_file("board-job.gbrjob", options).unwrap();
        writer.write_all(&job_bytes).unwrap();
        let package = writer.finish().unwrap().into_inner();
        let gerbers = BTreeMap::from([
            ("board-F_Cu.gtl".to_string(), (1, hash.clone())),
            ("board-B_Cu.gbl".to_string(), (1, hash.clone())),
            ("board-f_mask.gts".to_string(), (1, hash.clone())),
            ("board-b_mask.gbs".to_string(), (1, hash.clone())),
            ("board-f_silkscreen.gto".to_string(), (1, hash.clone())),
            ("board-b_silkscreen.gbo".to_string(), (1, hash.clone())),
            ("board-Edge_Cuts.gm1".to_string(), (1, hash.clone())),
            (
                "board-job.gbrjob".to_string(),
                (job_bytes.len() as u64, sha256(&job_bytes)),
            ),
        ]);
        let error = validate_gerber_job(&package, "board-job.gbrjob", &gerbers).unwrap_err();
        assert!(error.contains("every declared copper layer"), "{error}");

        let three_layer_job = json!({
            "GeneralSpecs": {"LayerNumber": 3},
            "FilesAttributes": [
                {"Path": "board-F_Cu.gtl", "FileFunction": "Copper,L1,Top"},
                {"Path": "board-In1_Cu.g2", "FileFunction": "Copper,L2,Inr"},
                {"Path": "board-B_Cu.gbl", "FileFunction": "Copper,L3,Bot"},
                {"Path": "board-f_mask.gts", "FileFunction": "SolderMask,Top"},
                {"Path": "board-b_mask.gbs", "FileFunction": "SolderMask,Bot"},
                {"Path": "board-f_silkscreen.gto", "FileFunction": "Legend,Top"},
                {"Path": "board-b_silkscreen.gbo", "FileFunction": "Legend,Bot"},
                {"Path": "board-Edge_Cuts.gm1", "FileFunction": "Profile"}
            ]
        });
        let three_layer_job_bytes = serde_json::to_vec(&three_layer_job).unwrap();
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        writer.start_file("board-job.gbrjob", options).unwrap();
        writer.write_all(&three_layer_job_bytes).unwrap();
        let three_layer_package = writer.finish().unwrap().into_inner();
        let mut three_layer_gerbers = gerbers;
        three_layer_gerbers.insert("board-In1_Cu.g2".to_string(), (1, hash));
        validate_gerber_job(
            &three_layer_package,
            "board-job.gbrjob",
            &three_layer_gerbers,
        )
        .unwrap();
    }

    #[test]
    fn validates_fixture_identity_and_rejects_tampering() {
        let input = b"board-bytes";
        let mut package = manufacturing_package();
        let expected_identity = ManufacturingPackageIdentity {
            input_path: "board.kicad_pcb".into(),
            input_bytes: input.len() as u64,
            input_sha256: sha256(input),
            physical_profile: None,
            dfm_profile: None,
        };
        assert_eq!(
            validate_manufacturing_package(&package).unwrap(),
            expected_identity
        );
        let details = validate_manufacturing_package_details(&package).unwrap();
        assert_eq!(details.identity, expected_identity);
        assert_eq!(details.manifest_parts_total, 0);
        assert_eq!(details.manifest_parts_bom, 0);
        assert_eq!(details.manifest_parts_placement, 0);
        assert_eq!(details.bom_bytes, TestManufacturingCsv::empty().bom);
        assert_eq!(details.cpl_bytes, TestManufacturingCsv::empty().cpl);
        assert_eq!(
            serde_json::from_slice::<Value>(&details.manifest_bytes).unwrap()["input"]["sha256"],
            sha256(input)
        );

        let index = {
            let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
            archive
                .by_name("board-F_Cu.gtl")
                .unwrap()
                .data_start()
                .unwrap() as usize
        };
        package[index] ^= 1;
        assert!(validate_manufacturing_package(&package).is_err());
    }

    #[test]
    fn validates_bom_and_cpl_csv_escaping_crlf_and_unicode() {
        let bom = concat!(
            "Comment,Designator,Footprint,Quantity,MPN,Layer,Type\r\n",
            "\"Res,\"\"value\"\"\r\nnext\",\"Rα,Rβ\",\"Foot,\"\"print\",2,\"MPN\r\nX\",F,SMD\r\n"
        )
        .as_bytes()
        .to_vec();
        let cpl = concat!(
            "Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n",
            "\"Rα,Rβ\",-9223372036854.775808,9223372036854.775807,-1.000,F\n"
        )
        .as_bytes()
        .to_vec();
        let package = manufacturing_package_with_csv(bom, cpl, 2, 1);
        validate_manufacturing_package(&package).unwrap();
    }

    #[test]
    fn validates_quoted_lone_line_breaks_controls_and_eof() {
        let bom = concat!(
            "Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n",
            "\"line one\rline two\nline three\",R\t1,\"Foot\rprint\",1,\"MPN\nvalue\",B,THT\n"
        )
        .as_bytes()
        .to_vec();
        let cpl = concat!(
            "Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\r\n",
            "R\t1,0.000000,-0.000001,0,B"
        )
        .as_bytes()
        .to_vec();
        let package = manufacturing_package_with_csv(bom, cpl, 1, 1);
        validate_manufacturing_package(&package).unwrap();
    }

    #[test]
    fn rejects_bom_cpl_csv_semantic_and_syntax_violations() {
        let bom_header = "Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n";
        let cpl_header = "Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n";
        let valid_bom = |quantity: &str, layer: &str, kind: &str| {
            format!("{bom_header}R1,R1,Footprint,{quantity},C123,{layer},{kind}\n").into_bytes()
        };
        let valid_cpl = |designator: &str, x: &str, y: &str, rotation: &str, layer: &str| {
            format!("{cpl_header}{designator},{x},{y},{rotation},{layer}\n").into_bytes()
        };

        for (bom, expected) in [
            (valid_bom("0", "F", "SMD"), "Quantity"),
            (valid_bom("18446744073709551616", "F", "SMD"), "Quantity"),
            (valid_bom("1", "X", "SMD"), "Layer"),
            (valid_bom("1", "F", "OTHER"), "Type"),
        ] {
            let package = manufacturing_package_with_csv(bom, cpl_header.as_bytes().to_vec(), 1, 0);
            let error = validate_manufacturing_package(&package).unwrap_err();
            assert!(
                error.contains("bom.csv") && error.contains(expected),
                "{error}"
            );
        }

        let package = manufacturing_package_with_csv(
            valid_bom("2", "F", "SMD"),
            valid_cpl("R1", "1e0", "2", "0", "F"),
            2,
            1,
        );
        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("cpl.csv") && error.contains("finite decimal"),
            "{error}"
        );

        let package = manufacturing_package_with_csv(
            valid_bom("1", "F", "SMD"),
            format!("{cpl_header}R1,1,2,0,F\nR1,3,4,0,F\n").into_bytes(),
            1,
            2,
        );
        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("cpl.csv") && error.contains("duplicate"),
            "{error}"
        );
    }

    #[test]
    fn rejects_csv_malformed_quotes_headers_and_counts() {
        let cpl_header = "Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n";
        let malformed_bom =
            b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n\"V,R1,F,1,M,F,SMD\n";
        let package = manufacturing_package_with_csv(
            malformed_bom.to_vec(),
            cpl_header.as_bytes().to_vec(),
            1,
            0,
        );
        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("bom.csv") && error.contains("unterminated"),
            "{error}"
        );

        let package = manufacturing_package_with_csv(
            b"Comment,Designator,Footprint,Quantity,MPN,Layer\n".to_vec(),
            cpl_header.as_bytes().to_vec(),
            0,
            0,
        );
        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("bom.csv") && error.contains("fields"),
            "{error}"
        );

        let bom = b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\nR1,R1,F,1,,F,SMD\n";
        let cpl =
            b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\nR1,9223372036854.775808,0,0,F\n";
        let package = manufacturing_package_with_csv(bom.to_vec(), cpl.to_vec(), 1, 1);
        let error = validate_manufacturing_package(&package).unwrap_err();
        assert!(
            error.contains("cpl.csv") && error.contains("checked range"),
            "{error}"
        );

        for (comment, expected) in [
            (b"bad\0value".as_slice(), "NUL"),
            (b"bad\xffvalue".as_slice(), "invalid UTF-8"),
        ] {
            let mut bom = b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n".to_vec();
            bom.extend_from_slice(comment);
            bom.extend_from_slice(b",R1,F,1,,F,SMD\n");
            let package = manufacturing_package_with_csv(bom, cpl_header.as_bytes().to_vec(), 1, 0);
            let error = validate_manufacturing_package(&package).unwrap_err();
            assert!(
                error.contains("bom.csv") && error.contains(expected),
                "{error}"
            );
        }
    }

    #[test]
    fn csv_parser_enforces_the_exact_data_row_limit() {
        let mut csv = Vec::with_capacity((MAX_MANUFACTURING_PARTS + 2) * 2);
        csv.extend_from_slice(b"H\n");
        for _ in 0..MAX_MANUFACTURING_PARTS {
            csv.extend_from_slice(b"x\n");
        }
        let mut records = 0_usize;
        parse_csv_reader(&mut Cursor::new(&csv), "limit.csv", 1, &mut |_, _, _| {
            records += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(records, MAX_MANUFACTURING_PARTS + 1);

        csv.extend_from_slice(b"x\n");
        let error = parse_csv_reader(
            &mut Cursor::new(&csv),
            "limit.csv",
            1,
            &mut |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("more than 100000 data rows"), "{error}");
    }

    #[test]
    fn validates_physical_profile_schema_and_rejects_cross_version_binding() {
        let binding = physical_profile_binding();
        let package = manufacturing_package_with_profile(
            b"front-copper".to_vec(),
            CompressionMethod::Stored,
            2,
            Some(&binding),
        );
        let identity = validate_manufacturing_package(&package).unwrap();
        assert_eq!(identity.physical_profile, Some(binding.clone()));

        let missing = manufacturing_package_with_profile(
            b"front-copper".to_vec(),
            CompressionMethod::Stored,
            2,
            None,
        );
        let error = validate_manufacturing_package(&missing).unwrap_err();
        assert!(
            error.contains("schema_version 2 requires physical_profile"),
            "{error}"
        );

        let extra = manufacturing_package_with_profile(
            b"front-copper".to_vec(),
            CompressionMethod::Stored,
            1,
            Some(&binding),
        );
        let error = validate_manufacturing_package(&extra).unwrap_err();
        assert!(
            error.contains("schema_version 1 must omit physical_profile"),
            "{error}"
        );
    }

    #[test]
    fn repair_identity_rejects_physical_profile_add_drop_and_substitution() {
        let binding = physical_profile_binding();
        let without = ManufacturingPackageIdentity {
            input_path: "board.kicad_pcb".into(),
            input_bytes: 1,
            input_sha256: "a".repeat(64),
            physical_profile: None,
            dfm_profile: None,
        };
        let with = ManufacturingPackageIdentity {
            physical_profile: Some(binding.clone()),
            ..without.clone()
        };
        assert!(validate_expected_physical_profile(&without, None).is_ok());
        assert!(validate_expected_physical_profile(&with, Some(&binding)).is_ok());
        assert!(validate_expected_physical_profile(&without, Some(&binding)).is_err());
        assert!(validate_expected_physical_profile(&with, None).is_err());

        let mut substituted = binding.clone();
        substituted.canonical_sha256 = "d".repeat(64);
        let substituted_identity = ManufacturingPackageIdentity {
            physical_profile: Some(substituted),
            ..without
        };
        assert!(validate_expected_physical_profile(&substituted_identity, Some(&binding)).is_err());
    }

    #[test]
    fn validates_dfm_profile_schema_v3_and_rejects_binding_changes() {
        let package = manufacturing_package_with_dfm_profile();
        let identity = validate_manufacturing_package(&package).unwrap();
        let binding = dfm_profile_binding();
        assert_eq!(identity.dfm_profile, Some(binding.clone()));
        assert!(validate_expected_dfm_profile(&identity, Some(&binding)).is_ok());
        assert!(validate_expected_dfm_profile(&identity, None).is_err());

        let mut substituted = binding;
        substituted.canonical_sha256 = "d".repeat(64);
        let substituted_identity = ManufacturingPackageIdentity {
            dfm_profile: Some(substituted),
            ..identity.clone()
        };
        assert!(
            validate_expected_dfm_profile(&substituted_identity, identity.dfm_profile.as_ref())
                .is_err()
        );

        let missing = rewrite_manifest(package.clone(), |manifest| {
            manifest["dfm_profile"] = Value::Null;
        });
        assert!(
            validate_manufacturing_package(&missing)
                .unwrap_err()
                .contains("schema_version 3 requires dfm_profile")
        );

        let legacy_with_dfm = rewrite_manifest(package, |manifest| {
            manifest["schema_version"] = json!(1);
        });
        assert!(
            validate_manufacturing_package(&legacy_with_dfm)
                .unwrap_err()
                .contains("schema_version 1")
        );
    }

    #[test]
    fn rejects_duplicate_top_level_and_nested_dfm_manifest_keys() {
        let package = manufacturing_package_with_dfm_profile();
        let manifest = String::from_utf8(manifest_bytes(&package)).unwrap();

        let mut top_level_duplicate = manifest.clone();
        let end = top_level_duplicate.rfind('}').unwrap();
        top_level_duplicate.insert_str(end, ",\"dfm_profile\":null");
        let top_level = replace_manifest_bytes(package.clone(), top_level_duplicate.as_bytes());
        let error = validate_manufacturing_package(&top_level).unwrap_err();
        assert!(error.contains("duplicate JSON object key"), "{error}");

        let binding = dfm_profile_binding();
        let canonical = binding.canonical_sha256;
        let needle = format!("\"canonical_sha256\":\"{canonical}\"");
        let replacement = format!("{needle},\"canonical_sha256\":\"{}\"", "0".repeat(64));
        let nested_duplicate = manifest.replacen(&needle, &replacement, 1);
        assert_ne!(nested_duplicate, manifest);
        let nested = replace_manifest_bytes(package, nested_duplicate.as_bytes());
        let error = validate_manufacturing_package(&nested).unwrap_err();
        assert!(error.contains("duplicate JSON object key"), "{error}");
    }

    #[test]
    fn accepts_archive_emitted_by_manufacturing_package_writer() {
        let staging = tempdir().unwrap();
        let job = json!({
            "GeneralSpecs": {"LayerNumber": 2},
            "FilesAttributes": [
                {"Path": "board-F_Cu.gtl", "FileFunction": "Copper,L1,Top"},
                {"Path": "board-B_Cu.gbl", "FileFunction": "Copper,L2,Bot"},
                {"Path": "board-f_mask.gts", "FileFunction": "SolderMask,Top"},
                {"Path": "board-b_mask.gbs", "FileFunction": "SolderMask,Bot"},
                {"Path": "board-f_silkscreen.gto", "FileFunction": "Legend,Top"},
                {"Path": "board-b_silkscreen.gbo", "FileFunction": "Legend,Bot"},
                {"Path": "board-Edge_Cuts.gm1", "FileFunction": "Profile"}
            ]
        });
        let files = [
            ("drc.rpt", b"DRC clean\n".as_slice()),
            ("board-F_Cu.gtl", b"front copper".as_slice()),
            ("board-B_Cu.gbl", b"back copper".as_slice()),
            ("board-f_mask.gts", b"front mask".as_slice()),
            ("board-b_mask.gbs", b"back mask".as_slice()),
            ("board-f_silkscreen.gto", b"front legend".as_slice()),
            ("board-b_silkscreen.gbo", b"back legend".as_slice()),
            ("board-Edge_Cuts.gm1", b"profile".as_slice()),
            ("board.drl", b"drill".as_slice()),
        ];
        let mut exported = Vec::new();
        for (name, bytes) in files {
            let path = staging.path().join(name);
            fs::write(&path, bytes).unwrap();
            exported.push(path);
        }
        let job_path = staging.path().join("board-job.gbrjob");
        fs::write(&job_path, serde_json::to_vec(&job).unwrap()).unwrap();
        exported.push(job_path);
        let archive = crate::manufacturing_package::write_manufacturing_package(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[crate::manufacturing_package::KiCadProjectInput {
                path: Path::new("board.kicad_pro").to_path_buf(),
                bytes: b"project".to_vec(),
            }],
            &[],
            &exported,
            &crate::manufacturing_package::KiCadIdentity {
                version: "10.0.5".into(),
                about_sha256: "a".repeat(64),
            },
        )
        .unwrap();
        let identity = validate_manufacturing_package(&fs::read(archive).unwrap()).unwrap();
        assert_eq!(
            identity,
            ManufacturingPackageIdentity {
                input_path: "board.kicad_pcb".into(),
                input_bytes: 5,
                input_sha256: sha256(b"board"),
                physical_profile: None,
                dfm_profile: None,
            }
        );
    }

    #[test]
    fn submits_valid_package_with_expected_request_and_deterministic_receipt() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let response_value = json!({
            "status": "  Quoted ",
            "accepted": true,
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
        assert!(validate_factory_submission_receipt(&receipt, true).is_ok());
        assert!(factory_feedback_passed(&receipt));
    }

    #[test]
    fn rejects_provider_responses_that_reflect_bearer_credentials() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        write_package(&package_path);
        let token = "secret-token-\"\\value";
        let response = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "echo": format!("authorization was Bearer {token}")
        }))
        .unwrap();
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", response, &[]);
        let variable = unique_env_name("PCBEX_FACTORY_REFLECTED_TOKEN");
        unsafe { env::set_var(&variable, token) };
        let result = submit_factory_package(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            Some(&variable),
            5,
            true,
        );
        unsafe { env::remove_var(&variable) };
        handle.join().unwrap();

        let error = result.unwrap_err();
        assert!(error.contains("reflected bearer credentials"), "{error}");
        assert!(!error.contains(token));
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
        let index = {
            let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
            archive
                .by_name("board-F_Cu.gtl")
                .unwrap()
                .data_start()
                .unwrap() as usize
        };
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

    #[cfg(unix)]
    #[test]
    fn rejects_factory_package_through_an_ancestor_symlink() {
        use std::os::unix::fs::symlink;

        let temporary = tempdir().unwrap();
        let real_parent = tempdir().unwrap();
        let package = real_parent.path().join("manufacturing.zip");
        fs::write(&package, b"package").unwrap();

        let linked_parent = temporary.path().join("linked-parent");
        symlink(real_parent.path(), &linked_parent).unwrap();
        let linked_package = linked_parent.join("manufacturing.zip");

        let error = read_package(&linked_package).unwrap_err();
        assert!(error.contains("reading factory package"), "{error}");
        assert!(error.to_ascii_lowercase().contains("symlink"), "{error}");
        assert_eq!(fs::read(&package).unwrap(), b"package");
    }

    #[test]
    fn feedback_loop_schema_is_closed_and_bounded() {
        let schema = factory_feedback_loop_json_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(schema["properties"]["schema_version"]["const"], 1);
        assert_eq!(
            schema["properties"]["attempts"]["maxItems"],
            MAX_REPAIR_ATTEMPTS
        );
        assert_eq!(
            schema["properties"]["attempts"]["items"]["additionalProperties"],
            false
        );
        assert!(
            schema["properties"]["attempts"]["items"]["required"]
                .as_array()
                .unwrap()
                .contains(&json!("error"))
        );
        assert_eq!(
            schema["properties"]["attempts"]["items"]["properties"]["receipt"]["anyOf"][1]["type"],
            "null"
        );
        assert_eq!(
            schema["properties"]["attempts"]["items"]["properties"]["error"]["minLength"],
            1
        );
        assert_eq!(
            schema["properties"]["attempts"]["items"]["properties"]["error"]["maxLength"],
            MAX_LOOP_ERROR_CHARS
        );
        assert_eq!(schema["properties"]["failure"]["minLength"], 1);
        assert_eq!(
            schema["properties"]["failure"]["maxLength"],
            MAX_LOOP_ERROR_CHARS
        );
        assert!(schema["allOf"].is_array());
        let receipt = &schema["$defs"]["factory_submission_receipt"];
        assert!(receipt.is_object());
        assert_eq!(
            receipt["properties"]["endpoint"]["anyOf"][0]["pattern"],
            "^https://[^/?#@]+(?:/[^?#]*)?$"
        );
        assert_eq!(
            receipt["properties"]["status"]["pattern"],
            "^\\S(?:[\\s\\S]*\\S)?$"
        );
        assert_eq!(
            receipt["properties"]["findings"]["items"]["properties"]["severity"]["pattern"],
            "^[^A-Z\\s](?:[^A-Z]*[^A-Z\\s])?$"
        );
        assert_eq!(
            schema["properties"]["final_package_bytes"]["maximum"],
            MAX_PACKAGE_BYTES
        );
        assert_eq!(
            bounded_loop_error(&"x".repeat(MAX_LOOP_ERROR_CHARS + 100))
                .chars()
                .count(),
            MAX_LOOP_ERROR_CHARS
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

    #[test]
    fn feedback_loop_preflights_limits_configuration_and_repair_before_package() {
        let error = run_factory_feedback_loop(
            Path::new("missing.zip"),
            "https://factory.example/quote",
            FactoryProvider::Generic,
            None,
            60,
            false,
            0,
            None,
        )
        .unwrap_err();
        assert!(error.contains("max_attempts"));

        let error = run_factory_feedback_loop(
            Path::new("missing.zip"),
            "https://factory.example/quote",
            FactoryProvider::Generic,
            None,
            0,
            false,
            1,
            None,
        )
        .unwrap_err();
        assert!(error.contains("timeout"), "{error}");

        let error = run_factory_feedback_loop(
            Path::new("missing.zip"),
            "http://factory.example/quote",
            FactoryProvider::Generic,
            None,
            60,
            false,
            1,
            None,
        )
        .unwrap_err();
        assert!(error.contains("HTTPS"), "{error}");

        let missing_variable = unique_env_name("PCBEX_FACTORY_MISSING_TOKEN");
        unsafe { env::remove_var(&missing_variable) };
        let error = run_factory_feedback_loop(
            Path::new("missing.zip"),
            "https://factory.example/quote",
            FactoryProvider::Generic,
            Some(&missing_variable),
            60,
            false,
            1,
            None,
        )
        .unwrap_err();
        assert!(error.contains("bearer-token"), "{error}");

        let error = run_factory_feedback_loop(
            Path::new("missing.zip"),
            "https://factory.example/quote",
            FactoryProvider::Generic,
            None,
            60,
            false,
            1,
            Some(Path::new("missing-repair-executable")),
        )
        .unwrap_err();
        assert!(error.contains("repair executable"), "{error}");

        let temporary = tempdir().unwrap();
        let non_file = temporary.path().join("repair-directory");
        fs::create_dir(&non_file).unwrap();
        let error = run_factory_feedback_loop(
            Path::new("missing.zip"),
            "https://factory.example/quote",
            FactoryProvider::Generic,
            None,
            60,
            false,
            1,
            Some(&non_file),
        )
        .unwrap_err();
        assert!(error.contains("regular file"), "{error}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let non_executable = temporary.path().join("not-executable.sh");
            fs::write(&non_executable, "#!/bin/sh\nexit 0\n").unwrap();
            let mut permissions = fs::metadata(&non_executable).unwrap().permissions();
            permissions.set_mode(0o600);
            fs::set_permissions(&non_executable, permissions).unwrap();
            let error = run_factory_feedback_loop(
                Path::new("missing.zip"),
                "https://factory.example/quote",
                FactoryProvider::Generic,
                None,
                60,
                false,
                1,
                Some(&non_executable),
            )
            .unwrap_err();
            assert!(error.contains("executable permission"), "{error}");
        }
    }

    #[test]
    fn feedback_loop_preserves_transport_failure_evidence_and_known_good_package() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let (endpoint, _received, handle) = spawn_http_fixture(
            503,
            "application/json",
            br#"{"status":"unavailable"}"#.to_vec(),
            &[],
        );

        let outcome = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            None,
        )
        .unwrap();
        handle.join().unwrap();

        assert!(!outcome.report.passed);
        assert_eq!(outcome.report.attempts.len(), 1);
        let attempt = &outcome.report.attempts[0];
        assert_eq!(attempt.package_sha256, sha256(&package));
        assert_eq!(attempt.package_bytes, package.len() as u64);
        assert!(attempt.receipt.is_none());
        assert!(!attempt.repair_command_ran);
        assert!(attempt.error.as_deref().unwrap().contains("HTTP"));
        assert_eq!(outcome.report.failure, attempt.error);
        assert_eq!(outcome.final_package, package);
        assert_eq!(outcome.report.final_package_sha256, sha256(&package));
    }

    #[cfg(unix)]
    #[test]
    fn feedback_loop_repairs_passes_rewound_receipt_and_isolates_token_environment() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": [{"severity": "error", "message": "clearance"}]
        }))
        .unwrap();
        let passed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }))
        .unwrap();
        let (endpoint, received, handle) = spawn_http_sequence(vec![failed, passed]);
        let token_variable = unique_env_name("PCBEX_FACTORY_LOOP_SECRET");
        let script = write_repair_script(
            temporary.path(),
            "repair.sh",
            &format!(
                "grep -q '\"dfm_passed\": false'\nif env | grep -q '^{}='; then exit 91; fi\ncp \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
                token_variable
            ),
        );
        unsafe { env::set_var(&token_variable, "super-secret-token") };
        let result = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            Some(&token_variable),
            5,
            true,
            2,
            Some(&script),
        );
        unsafe { env::remove_var(&token_variable) };
        let outcome = result.unwrap();
        handle.join().unwrap();

        assert!(outcome.report.passed);
        assert_eq!(outcome.report.attempts.len(), 2);
        assert!(outcome.report.attempts[0].receipt.is_some());
        assert!(outcome.report.attempts[0].error.is_none());
        assert!(outcome.report.attempts[0].repair_command_ran);
        assert!(!outcome.report.attempts[1].repair_command_ran);
        assert!(outcome.report.attempts[1].error.is_none());
        assert_eq!(outcome.final_package, package);
        assert_eq!(received.lock().unwrap().len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn feedback_loop_executes_repair_from_non_utf8_path() {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};

        let temporary = tempdir().unwrap();
        let package_path = temporary
            .path()
            .join(OsString::from_vec(b"manufacturing-\xff.zip".to_vec()));
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let passed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) = spawn_http_sequence(vec![failed, passed]);
        let executable_name = OsString::from_vec(b"repair-\xfe".to_vec());
        let script = write_repair_script(
            temporary.path(),
            &executable_name,
            "cp \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
        );

        let outcome = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
        )
        .unwrap();
        handle.join().unwrap();

        assert!(outcome.report.passed);
        assert!(outcome.report.attempts[0].repair_command_ran);
        assert_eq!(outcome.final_package, package);
    }

    #[cfg(unix)]
    #[test]
    fn repair_with_large_receipt_does_not_block_when_child_ignores_stdin() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "opaque": "x".repeat(256 * 1024)
        }))
        .unwrap();
        let passed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) = spawn_http_sequence(vec![failed, passed]);
        let script = write_repair_script(
            temporary.path(),
            "ignore-stdin.sh",
            "cp \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
        );

        let started = Instant::now();
        let outcome = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
        )
        .unwrap();
        handle.join().unwrap();

        assert!(outcome.report.passed);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(outcome.final_package, package);
    }

    #[cfg(unix)]
    #[test]
    fn repair_mutation_and_invalid_output_never_replace_known_good_bytes() {
        let cases = [
            (
                "mutate.sh",
                "printf tampered > \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\"\nprintf invalid > \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
                "modified its input package",
            ),
            (
                "invalid.sh",
                "printf not-a-package > \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
                "not a valid manufacturing package",
            ),
            (
                "symlink.sh",
                "rm -f \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"\nln -s \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
                "symlink",
            ),
        ];
        for (name, body, expected) in cases {
            let temporary = tempdir().unwrap();
            let package_path = temporary.path().join("manufacturing.zip");
            let package = write_package(&package_path);
            let failed = serde_json::to_vec(&json!({
                "status": "quoted",
                "accepted": true,
                "dfm_passed": false,
                "findings": []
            }))
            .unwrap();
            let (endpoint, _received, handle) =
                spawn_http_fixture(200, "application/json", failed, &[]);
            let script = write_repair_script(temporary.path(), name, body);

            let outcome = run_factory_feedback_loop(
                &package_path,
                &endpoint,
                FactoryProvider::Generic,
                None,
                5,
                true,
                2,
                Some(&script),
            )
            .unwrap();
            handle.join().unwrap();

            assert!(!outcome.report.passed);
            assert_eq!(outcome.report.attempts.len(), 1);
            let attempt = &outcome.report.attempts[0];
            assert!(attempt.receipt.is_some());
            assert!(attempt.repair_command_ran);
            assert!(attempt.error.as_deref().unwrap().contains(expected));
            assert_eq!(outcome.final_package, package);
            assert_eq!(outcome.report.final_package_sha256, sha256(&package));
        }
    }

    #[cfg(unix)]
    #[test]
    fn repair_workspace_quota_failure_preserves_known_good_package_and_evidence() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", failed, &[]);
        let script = write_repair_script(
            temporary.path(),
            "workspace-overage.sh",
            "cp \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"\nhead -c 8192 /dev/zero > workspace-overage.bin",
        );
        let mut manufacturing = ManufacturingLimits::production();
        manufacturing.max_total_bytes = package.len() as u64 * 2 + 1024;
        let limits = FactoryLoopLimits {
            total: Duration::from_secs(3),
            repair: Duration::from_secs(1),
            manufacturing,
        };

        let outcome = run_factory_feedback_loop_with_limits(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
            limits,
        )
        .unwrap();
        handle.join().unwrap();

        assert!(!outcome.report.passed);
        assert_eq!(outcome.report.attempts.len(), 1);
        let attempt = &outcome.report.attempts[0];
        assert!(attempt.repair_command_ran);
        assert!(attempt.error.as_deref().unwrap().contains("workspace"));
        assert_eq!(outcome.final_package, package);
        assert_eq!(outcome.report.final_package_sha256, sha256(&package));
    }

    #[cfg(unix)]
    #[test]
    fn repair_nonzero_exit_preserves_known_good_package_and_status_evidence() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", failed, &[]);
        let script = write_repair_script(temporary.path(), "exit-seven.sh", "exit 7");

        let outcome = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
        )
        .unwrap();
        handle.join().unwrap();

        assert!(!outcome.report.passed);
        assert_eq!(outcome.report.attempts.len(), 1);
        let attempt = &outcome.report.attempts[0];
        assert!(attempt.receipt.is_some());
        assert!(attempt.repair_command_ran);
        assert_eq!(
            attempt.error.as_deref(),
            Some("factory repair command failed with exit status: 7")
        );
        assert_eq!(outcome.final_package, package);
        assert_eq!(outcome.report.final_package_sha256, sha256(&package));
    }

    #[cfg(unix)]
    #[test]
    fn repair_missing_executable_reports_spawn_without_running_command() {
        let temporary = tempdir().unwrap();
        let package = manufacturing_package();
        let snapshot = snapshot_known_good(temporary.path(), "initial-", package).unwrap();
        let receipt = receipt_for_response(json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }));
        let missing = temporary.path().join("missing-repair-command");

        let outcome = run_repair_command(RepairCommandRequest {
            executable: &missing,
            current_package: &snapshot,
            receipt: &receipt,
            workspace: temporary.path(),
            timeout: Duration::from_secs(1),
            bearer_token_env: None,
            manufacturing_limits: ManufacturingLimits::production(),
            expected_physical_profile: None,
            expected_dfm_profile: None,
        });

        assert!(!outcome.command_ran);
        assert!(
            outcome
                .result
                .as_ref()
                .unwrap_err()
                .starts_with("starting factory repair command:")
        );
    }

    #[cfg(unix)]
    #[test]
    fn repair_timeout_is_bounded_by_internal_short_limit_and_keeps_input() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", failed, &[]);
        let script = write_repair_script(temporary.path(), "hang.sh", "while :; do :; done");
        let limits = FactoryLoopLimits {
            total: Duration::from_secs(3),
            repair: Duration::from_millis(100),
            manufacturing: ManufacturingLimits::production(),
        };

        let started = Instant::now();
        let outcome = run_factory_feedback_loop_with_limits(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
            limits,
        )
        .unwrap();
        handle.join().unwrap();

        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!outcome.report.passed);
        assert!(outcome.report.attempts[0].repair_command_ran);
        assert!(
            outcome.report.attempts[0]
                .error
                .as_deref()
                .unwrap()
                .contains("exceeded")
        );
        assert_eq!(outcome.final_package, package);
    }

    #[cfg(unix)]
    #[test]
    fn repair_success_kills_background_descendant() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let passed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": true,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) = spawn_http_sequence(vec![failed, passed]);
        let marker = temporary.path().join("success-descendant-marker");
        let script = write_repair_script(
            temporary.path(),
            "success-descendant.sh",
            &format!(
                "(sleep 0.25; printf leaked > '{}') >/dev/null 2>&1 &\ncp \"$PCBEX_FACTORY_REPAIR_INPUT_PACKAGE\" \"$PCBEX_FACTORY_REPAIR_OUTPUT_PACKAGE\"",
                marker.display()
            ),
        );

        let outcome = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
        )
        .unwrap();
        handle.join().unwrap();

        assert!(outcome.report.passed);
        assert!(outcome.report.attempts[0].repair_command_ran);
        assert_eq!(outcome.final_package, package);
        thread::sleep(Duration::from_millis(350));
        assert!(
            !marker.exists(),
            "successful repair left a descendant running"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repair_timeout_kills_background_descendant() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", failed, &[]);
        let marker = temporary.path().join("timeout-descendant-marker");
        let script = write_repair_script(
            temporary.path(),
            "timeout-descendant.sh",
            &format!(
                "(sleep 0.25; printf leaked > '{}') >/dev/null 2>&1 &\nwhile :; do :; done",
                marker.display()
            ),
        );
        let limits = FactoryLoopLimits {
            total: Duration::from_secs(3),
            repair: Duration::from_millis(100),
            manufacturing: ManufacturingLimits::production(),
        };

        let outcome = run_factory_feedback_loop_with_limits(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
            limits,
        )
        .unwrap();
        handle.join().unwrap();

        assert!(!outcome.report.passed);
        assert!(outcome.report.attempts[0].repair_command_ran);
        assert!(
            outcome.report.attempts[0]
                .error
                .as_deref()
                .unwrap()
                .contains("factory repair command exceeded 100 milliseconds")
        );
        assert_eq!(outcome.final_package, package);
        thread::sleep(Duration::from_millis(350));
        assert!(
            !marker.exists(),
            "timed-out repair left a descendant running"
        );
    }

    #[cfg(unix)]
    #[test]
    fn repair_output_limit_preserves_known_good_package_and_error_evidence() {
        let temporary = tempdir().unwrap();
        let package_path = temporary.path().join("manufacturing.zip");
        let package = write_package(&package_path);
        let failed = serde_json::to_vec(&json!({
            "status": "quoted",
            "accepted": true,
            "dfm_passed": false,
            "findings": []
        }))
        .unwrap();
        let (endpoint, _received, handle) =
            spawn_http_fixture(200, "application/json", failed, &[]);
        let script = write_repair_script(
            temporary.path(),
            "stdout-limit.sh",
            "head -c 1048577 /dev/zero",
        );

        let outcome = run_factory_feedback_loop(
            &package_path,
            &endpoint,
            FactoryProvider::Generic,
            None,
            5,
            true,
            2,
            Some(&script),
        )
        .unwrap();
        handle.join().unwrap();

        assert!(!outcome.report.passed);
        assert_eq!(outcome.report.attempts.len(), 1);
        let attempt = &outcome.report.attempts[0];
        assert!(attempt.receipt.is_some());
        assert!(attempt.repair_command_ran);
        assert!(
            attempt.error.as_deref().unwrap().contains(
                "factory repair command failed: subprocess stdout exceeded 1048576 bytes"
            )
        );
        assert_eq!(outcome.final_package, package);
        assert_eq!(outcome.report.final_package_sha256, sha256(&package));
    }

    #[test]
    fn network_timeout_is_capped_to_whole_seconds_remaining() {
        let deadline = Instant::now() + Duration::from_millis(2_500);
        let bounded = bounded_network_timeout(deadline, 600).unwrap();
        assert!((1..=2).contains(&bounded), "{bounded}");
        assert!(bounded_network_timeout(Instant::now(), 600).is_none());
    }
}
