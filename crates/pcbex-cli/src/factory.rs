//! Bounded factory quote and DFM-feedback adapters.
//!
//! Provider APIs change independently of pcbex.  The adapter therefore sends a
//! documented raw manufacturing ZIP over HTTPS and normalizes the JSON response
//! into a stable receipt.  Provider-specific authentication and endpoint paths
//! remain configuration, never source-code secrets.

use crate::bounded_process::{ProcessError, ProcessLimits, run_bounded_with_stdin_file};
use crate::manufacturing_limits::{
    MAX_ARCHIVE_ENTRIES, MAX_ARCHIVE_UNCOMPRESSED_BYTES, MAX_MANIFEST_BYTES, MAX_PACKAGE_BYTES,
    ManufacturingLimits, portable_manufacturing_name_key, scan_manufacturing_workspace,
    validate_manufacturing_basename,
};
use crate::physical_profile::{PhysicalProfileBinding, validate_physical_profile_binding};
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ManufacturingPackageIdentity {
    pub(crate) input_path: String,
    pub(crate) input_bytes: u64,
    pub(crate) input_sha256: String,
    pub(crate) physical_profile: Option<PhysicalProfileBinding>,
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

fn validate_manufacturing_package_with_expanded_limit(
    package: &[u8],
    max_expanded_bytes: u64,
) -> Result<ManufacturingPackageIdentity, String> {
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
    let manifest_value: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("factory package manifest.json is not valid JSON: {error}"))?;
    let manifest: ManufacturingManifest = serde_json::from_value(manifest_value.clone())
        .map_err(|error| format!("factory package manifest.json is not valid JSON: {error}"))?;
    let physical_profile_present = manifest_value
        .as_object()
        .is_some_and(|object| object.contains_key("physical_profile"));
    let physical_profile = match (
        manifest.schema_version,
        physical_profile_present,
        manifest.physical_profile.as_ref(),
    ) {
        (1, false, None) => None,
        (1, true, _) => {
            return Err(
                "factory package manifest.json schema_version 1 must omit physical_profile".into(),
            );
        }
        (2, false, _) => {
            return Err(
                "factory package manifest.json schema_version 2 requires physical_profile".into(),
            );
        }
        (2, true, Some(binding)) => {
            validate_physical_profile_binding(binding).map_err(|error| {
                format!("factory package manifest.json physical_profile is invalid: {error:#}")
            })?;
            Some(binding.clone())
        }
        (2, true, None) => {
            return Err(
                "factory package manifest.json schema_version 2 requires physical_profile".into(),
            );
        }
        _ => {
            return Err(
                "factory package manifest.json schema_version must be 1 without physical_profile or 2 with physical_profile"
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
    };
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
    Ok(identity)
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
            ("bom.csv", b"Comment,Designator\n".to_vec()),
            ("cpl.csv", b"Designator,Mid X (mm)\n".to_vec()),
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
            "parts": {"total": 0, "bom": 0, "placement": 0, "dnp": 0},
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
    fn aggregate_archive_limit_uses_actual_decompressed_bytes() {
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

        let declared_total = {
            let mut archive = ZipArchive::new(Cursor::new(package.as_slice())).unwrap();
            let mut total = 0_u64;
            for index in 0..archive.len() {
                let entry = archive.by_index(index).unwrap();
                if entry.name() != "manifest.json" {
                    total += entry.size();
                }
            }
            total
        };

        // The package is otherwise valid under the production cap.  A test
        // cap equal to the forged declarations must still reject it because
        // the streamed payload is larger than those declarations.
        validate_manufacturing_package(&package).unwrap();
        let error = validate_manufacturing_package_with_expanded_limit(&package, declared_total)
            .unwrap_err();
        assert!(
            error.contains("decompressed artifact bytes exceed"),
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
        assert_eq!(
            validate_manufacturing_package(&package).unwrap(),
            ManufacturingPackageIdentity {
                input_path: "board.kicad_pcb".into(),
                input_bytes: input.len() as u64,
                input_sha256: sha256(input),
                physical_profile: None,
            }
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
