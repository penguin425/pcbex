//! Fresh, source-bound verification of a generated firmware bundle.
//!
//! The verifier accepts captured bytes and logical identities rather than
//! caller filesystem paths. It validates a complete v2 bundle, reconstructs
//! the six current commands from bare tool names, and runs each language
//! family in its own private stage. A build failure is retained as rejected
//! evidence; cancellation is an error and never yields a report.

use super::{
    COMMAND_TEXT_PATTERN, FIRMWARE_ARTIFACTS, FIRMWARE_SCHEMA_VERSION, FirmwareArtifact,
    FirmwareBuildEvidence, FirmwareManifest, MAX_COMMAND_ARGUMENTS, MAX_COMMAND_TEXT,
    MAX_ENGINE_VERSION, MAX_FIRMWARE_ARTIFACT_BYTES, MAX_TOTAL_ARTIFACT_BYTES, validate_tool_name,
};
use crate::bounded_io::{opened_path_matches, same_file};
use crate::bounded_process::{ProcessError, ProcessLimits, run_bounded};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub(crate) const FRESH_FIRMWARE_BUILD_REPORT_SCHEMA_VERSION: u32 = 1;
pub(crate) const FRESH_FIRMWARE_BUILD_SCOPE: &str = "fresh_firmware_bundle_build_v1";
pub(crate) const FRESH_FIRMWARE_BUILD_MAX_REPORT_BYTES: usize = 1024 * 1024;
pub(crate) const FRESH_FIRMWARE_BUILD_STDOUT_BYTES: usize = 1024 * 1024;
pub(crate) const FRESH_FIRMWARE_BUILD_STDERR_BYTES: usize = 1024 * 1024;
pub(crate) const FRESH_FIRMWARE_BUILD_MAX_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
const MAX_TIMEOUT_SECONDS: u64 = 3600;

const CHECK_NAMES: [&str; 6] = [
    "c_compile",
    "c_smoke",
    "cpp_compile",
    "cpp_smoke",
    "python_compile",
    "python_self_test",
];

#[cfg(not(windows))]
const C_OUTPUT: &str = ".pcbex-firmware-c-smoke";
#[cfg(windows)]
const C_OUTPUT: &str = ".pcbex-firmware-c-smoke.exe";
#[cfg(not(windows))]
const CPP_OUTPUT: &str = ".pcbex-firmware-cpp-smoke";
#[cfg(windows)]
const CPP_OUTPUT: &str = ".pcbex-firmware-cpp-smoke.exe";

/// One caller-captured source. `identity.path` is a logical bundle leaf, not
/// a caller filesystem path; its byte count and digest are independently
/// checked against `contents` and the retained manifest.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshFirmwareBuildArtifactInput<'a> {
    pub(crate) identity: &'a FirmwareArtifact,
    pub(crate) contents: &'a [u8],
}

/// All path-free inputs needed for a fresh build.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshFirmwareBuildInput<'a> {
    pub(crate) manifest_bytes: &'a [u8],
    pub(crate) artifacts: &'a [FreshFirmwareBuildArtifactInput<'a>],
}

/// Current tool selections and the independent deadline applied to each
/// child. Tool values must be bare executable names resolved through PATH.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FreshFirmwareBuildOptions<'a> {
    pub(crate) cc: &'a str,
    pub(crate) cxx: &'a str,
    pub(crate) python: &'a str,
    pub(crate) timeout: Duration,
}

impl<'a> Default for FreshFirmwareBuildOptions<'a> {
    fn default() -> Self {
        Self {
            cc: "cc",
            cxx: "c++",
            python: "python3",
            timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreshFirmwareBuildFileIdentity {
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreshFirmwareBuildBundle {
    pub(crate) manifest: FreshFirmwareBuildFileIdentity,
    pub(crate) manifest_schema_version: u32,
    pub(crate) schematic_sha256: String,
    pub(crate) artifacts: Vec<FirmwareArtifact>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FreshFirmwareBuildFailure {
    DependencyFailed,
    ExitFailure,
    MissingOutput,
    SpawnFailure,
    Timeout,
    StdoutLimit,
    StderrLimit,
    SupervisionFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreshFirmwareBuildCheck {
    pub(crate) name: String,
    pub(crate) command: Vec<String>,
    pub(crate) attempted: bool,
    pub(crate) passed: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) failure: Option<FreshFirmwareBuildFailure>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreshFirmwareBuildProcessLimits {
    pub(crate) timeout_seconds: u64,
    pub(crate) stdout_bytes: usize,
    pub(crate) stderr_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreshFirmwareBuildReport {
    pub(crate) schema_version: u32,
    pub(crate) scope: String,
    pub(crate) engine_version: String,
    pub(crate) bundle: FreshFirmwareBuildBundle,
    pub(crate) process_limits: FreshFirmwareBuildProcessLimits,
    pub(crate) checks: Vec<FreshFirmwareBuildCheck>,
    pub(crate) toolchain_provenance_verified: bool,
    pub(crate) approved: bool,
}

/// Validate the retained v2 manifest and exact seven captured sources, then
/// run a fresh compile/smoke sequence. Process failures are report evidence;
/// cancellation and invalid inputs are hard errors.
pub(crate) fn verify_fresh_firmware_bundle_build(
    input: FreshFirmwareBuildInput<'_>,
    options: FreshFirmwareBuildOptions<'_>,
    cancellation: Option<&AtomicBool>,
) -> Result<FreshFirmwareBuildReport> {
    ensure_not_cancelled(cancellation)?;
    validate_options(options)?;
    let manifest = decode_exact_manifest(input.manifest_bytes)?;
    validate_captured_artifacts(&manifest, input.artifacts)?;
    ensure_not_cancelled(cancellation)?;

    // Separate stages prevent a hostile or defective check in one language
    // family from changing the inputs later families observe.
    let private_root = tempfile::Builder::new()
        .prefix("pcbex-fresh-firmware-build-")
        .tempdir()
        .context("creating private fresh firmware build directory")?;
    let c_stage = create_stage(private_root.path(), "c", input.artifacts)?;
    let cpp_stage = create_stage(private_root.path(), "cpp", input.artifacts)?;
    let python_stage = create_stage(private_root.path(), "python", input.artifacts)?;

    let c_compile_command = c_compile_command(options.cc);
    let mut c_compile = run_check(
        CHECK_NAMES[0],
        &c_compile_command,
        &c_stage,
        None,
        options.timeout,
        cancellation,
    )?;
    enforce_stage_integrity(&c_compile, &c_stage, input.artifacts)?;
    let c_program = if c_compile.passed {
        validate_compiled_output(&c_stage.join(C_OUTPUT), &mut c_compile)
    } else {
        None
    };
    let c_smoke = if let Some(program) = c_program {
        run_check(
            CHECK_NAMES[1],
            &c_smoke_command(),
            &c_stage,
            Some(&program),
            options.timeout,
            cancellation,
        )?
    } else {
        dependency_check(CHECK_NAMES[1], c_smoke_command())
    };
    enforce_stage_integrity(&c_smoke, &c_stage, input.artifacts)?;
    ensure_not_cancelled(cancellation)?;

    let cpp_compile_command = cpp_compile_command(options.cxx);
    let mut cpp_compile = run_check(
        CHECK_NAMES[2],
        &cpp_compile_command,
        &cpp_stage,
        None,
        options.timeout,
        cancellation,
    )?;
    enforce_stage_integrity(&cpp_compile, &cpp_stage, input.artifacts)?;
    let cpp_program = if cpp_compile.passed {
        validate_compiled_output(&cpp_stage.join(CPP_OUTPUT), &mut cpp_compile)
    } else {
        None
    };
    let cpp_smoke = if let Some(program) = cpp_program {
        run_check(
            CHECK_NAMES[3],
            &cpp_smoke_command(),
            &cpp_stage,
            Some(&program),
            options.timeout,
            cancellation,
        )?
    } else {
        dependency_check(CHECK_NAMES[3], cpp_smoke_command())
    };
    enforce_stage_integrity(&cpp_smoke, &cpp_stage, input.artifacts)?;
    ensure_not_cancelled(cancellation)?;

    let python_compile_command = python_compile_command(options.python);
    let mut python_compile = run_check(
        CHECK_NAMES[4],
        &python_compile_command,
        &python_stage,
        None,
        options.timeout,
        cancellation,
    )?;
    enforce_stage_integrity(&python_compile, &python_stage, input.artifacts)?;
    if python_compile.passed && !python_bytecode_is_present(&python_stage) {
        mark_failed(
            &mut python_compile,
            FreshFirmwareBuildFailure::MissingOutput,
        );
    }
    let python_self_test = if python_compile.passed {
        let command = python_self_test_command(options.python);
        run_check(
            CHECK_NAMES[5],
            &command,
            &python_stage,
            None,
            options.timeout,
            cancellation,
        )?
    } else {
        dependency_check(CHECK_NAMES[5], python_self_test_command(options.python))
    };
    enforce_stage_integrity(&python_self_test, &python_stage, input.artifacts)?;
    ensure_not_cancelled(cancellation)?;

    // Recheck every isolated stage after every child has exited. This catches
    // delayed mutation by a tool before any evidence can be returned.
    for stage in [&c_stage, &cpp_stage, &python_stage] {
        if !stage_has_exact_sources(stage, input.artifacts, false) {
            bail!("fresh firmware source stage changed during build verification")
        }
    }
    ensure_not_cancelled(cancellation)?;

    let checks = vec![
        c_compile,
        c_smoke,
        cpp_compile,
        cpp_smoke,
        python_compile,
        python_self_test,
    ];
    let approved = checks.iter().all(|check| check.passed);
    let report = FreshFirmwareBuildReport {
        schema_version: FRESH_FIRMWARE_BUILD_REPORT_SCHEMA_VERSION,
        scope: FRESH_FIRMWARE_BUILD_SCOPE.to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        bundle: FreshFirmwareBuildBundle {
            manifest: identity(input.manifest_bytes),
            manifest_schema_version: FIRMWARE_SCHEMA_VERSION,
            schematic_sha256: manifest.schematic_sha256,
            artifacts: manifest.artifacts,
        },
        process_limits: FreshFirmwareBuildProcessLimits {
            timeout_seconds: options.timeout.as_secs(),
            stdout_bytes: FRESH_FIRMWARE_BUILD_STDOUT_BYTES,
            stderr_bytes: FRESH_FIRMWARE_BUILD_STDERR_BYTES,
        },
        checks,
        toolchain_provenance_verified: false,
        approved,
    };
    validate_fresh_firmware_build_report(&report)?;
    ensure_not_cancelled(cancellation)?;
    Ok(report)
}

fn validate_options(options: FreshFirmwareBuildOptions<'_>) -> Result<()> {
    validate_tool_name(options.cc, "fresh firmware C compiler")?;
    validate_tool_name(options.cxx, "fresh firmware C++ compiler")?;
    validate_tool_name(options.python, "fresh firmware Python interpreter")?;
    let seconds = options.timeout.as_secs();
    if seconds == 0
        || seconds > MAX_TIMEOUT_SECONDS
        || options.timeout != Duration::from_secs(seconds)
    {
        bail!(
            "fresh firmware process timeout must be a whole number of seconds between 1 and {MAX_TIMEOUT_SECONDS}"
        )
    }
    Ok(())
}

fn ensure_not_cancelled(cancellation: Option<&AtomicBool>) -> Result<()> {
    if cancellation.is_some_and(|flag| flag.load(Ordering::SeqCst)) {
        bail!("fresh firmware bundle build cancelled")
    }
    Ok(())
}

fn decode_exact_manifest(bytes: &[u8]) -> Result<FirmwareManifest> {
    if bytes.is_empty() {
        bail!("firmware bundle manifest is empty")
    }
    if bytes.len() > FRESH_FIRMWARE_BUILD_MAX_MANIFEST_BYTES {
        bail!("firmware bundle manifest exceeds {FRESH_FIRMWARE_BUILD_MAX_MANIFEST_BYTES} bytes")
    }
    reject_duplicate_json_keys(bytes).context("decoding exact v2 firmware bundle manifest")?;
    let manifest: FirmwareManifest =
        serde_json::from_slice(bytes).context("decoding exact v2 firmware bundle manifest")?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_manifest(manifest: &FirmwareManifest) -> Result<()> {
    if manifest.schema_version != FIRMWARE_SCHEMA_VERSION || manifest.engine != "pcbex" {
        bail!("firmware bundle manifest version or engine is invalid")
    }
    if !valid_engine_version(&manifest.engine_version) {
        bail!("firmware bundle manifest engine version is invalid")
    }
    validate_sha256(&manifest.schematic_sha256, "firmware schematic")?;
    validate_artifact_descriptors(&manifest.artifacts)?;
    validate_manifest_build(&manifest.c_build, "C build")?;
    validate_manifest_build(&manifest.cpp_build, "C++ build")?;
    validate_manifest_build(&manifest.python_check, "Python check")?;
    Ok(())
}

fn validate_manifest_build(build: &FirmwareBuildEvidence, label: &str) -> Result<()> {
    validate_manifest_command_state(
        build.attempted,
        build.passed,
        &build.command,
        build.exit_code,
        label,
        true,
    )?;
    validate_manifest_command_state(
        build.smoke.attempted,
        build.smoke.passed,
        &build.smoke.command,
        build.smoke.exit_code,
        &format!("{label} smoke"),
        false,
    )?;
    if !build.attempted && (build.passed || build.exit_code.is_some() || build.smoke.attempted) {
        bail!("firmware bundle manifest {label} skipped-state invariant is invalid")
    }
    if build.passed
        && (!build.attempted
            || build.exit_code != Some(0)
            || !build.smoke.attempted
            || !build.smoke.passed
            || build.smoke.exit_code != Some(0))
    {
        bail!("firmware bundle manifest {label} passed-state invariant is invalid")
    }
    if !build.smoke.attempted && build.passed {
        bail!("firmware bundle manifest {label} smoke dependency invariant is invalid")
    }
    if build.smoke.attempted && (!build.attempted || build.exit_code != Some(0)) {
        bail!("firmware bundle manifest {label} smoke attempt invariant is invalid")
    }
    if build.smoke.passed && !build.passed {
        bail!("firmware bundle manifest {label} aggregate result is invalid")
    }
    if build.attempted && build.exit_code != Some(0) && build.smoke.attempted {
        bail!("firmware bundle manifest {label} failed compile ran its smoke check")
    }
    Ok(())
}

fn validate_manifest_command_state(
    attempted: bool,
    passed: bool,
    command: &[String],
    exit_code: Option<i32>,
    label: &str,
    aggregate_build: bool,
) -> Result<()> {
    if command.is_empty() || command.len() > MAX_COMMAND_ARGUMENTS {
        bail!("firmware bundle manifest {label} command length is invalid")
    }
    for argument in command {
        if !valid_command_text(argument) {
            bail!("firmware bundle manifest {label} command text is invalid")
        }
    }
    if !attempted && (passed || exit_code.is_some()) {
        bail!("firmware bundle manifest {label} skipped result is invalid")
    }
    if passed && (!attempted || exit_code != Some(0)) {
        bail!("firmware bundle manifest {label} passed result is invalid")
    }
    if attempted && !passed && exit_code == Some(0) && !aggregate_build {
        bail!("firmware bundle manifest {label} failed result is invalid")
    }
    Ok(())
}

fn valid_command_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_COMMAND_TEXT
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_graphic()
        && value.as_bytes()[value.len() - 1].is_ascii_graphic()
        && value
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
}

fn valid_engine_version(value: &str) -> bool {
    if value.len() < 5 || value.len() > MAX_ENGINE_VERSION || !value.is_ascii() {
        return false;
    }
    let mut plus = value.split('+');
    let core_and_pre = plus.next().unwrap_or_default();
    let build = plus.next();
    if plus.next().is_some() || build.is_some_and(|part| part.is_empty() || !version_suffix(part)) {
        return false;
    }
    let (core, pre) = core_and_pre
        .split_once('-')
        .map_or((core_and_pre, None), |(core, pre)| (core, Some(pre)));
    if pre.is_some_and(|part| part.is_empty() || !version_suffix(part)) {
        return false;
    }
    let mut numbers = core.split('.');
    (0..3).all(|_| {
        numbers
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }) && numbers.next().is_none()
}

fn version_suffix(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn validate_artifact_descriptors(artifacts: &[FirmwareArtifact]) -> Result<()> {
    if artifacts.len() != FIRMWARE_ARTIFACTS.len() {
        bail!("firmware bundle manifest must describe exactly seven artifacts")
    }
    let mut total = 0u64;
    for (artifact, expected_path) in artifacts.iter().zip(FIRMWARE_ARTIFACTS) {
        if artifact.path != expected_path {
            bail!("firmware bundle manifest artifact order or path is invalid")
        }
        if artifact.bytes == 0 || artifact.bytes > MAX_FIRMWARE_ARTIFACT_BYTES {
            bail!("firmware bundle manifest artifact byte count is invalid")
        }
        total = total
            .checked_add(artifact.bytes)
            .ok_or_else(|| anyhow!("firmware bundle artifact byte count overflow"))?;
        if total > MAX_TOTAL_ARTIFACT_BYTES {
            bail!("firmware bundle artifacts exceed the total byte limit")
        }
        validate_sha256(&artifact.sha256, "firmware artifact")?;
    }
    Ok(())
}

fn validate_captured_artifacts(
    manifest: &FirmwareManifest,
    captures: &[FreshFirmwareBuildArtifactInput<'_>],
) -> Result<()> {
    if captures.len() != FIRMWARE_ARTIFACTS.len() {
        bail!("fresh firmware build requires exactly seven captured artifacts")
    }
    for ((capture, retained), expected_path) in captures
        .iter()
        .zip(&manifest.artifacts)
        .zip(FIRMWARE_ARTIFACTS)
    {
        if capture.identity.path != expected_path || capture.identity != retained {
            bail!("captured firmware artifact identity does not match the v2 manifest")
        }
        let actual = identity(capture.contents);
        if capture.identity.bytes != actual.bytes
            || capture.identity.sha256 != actual.sha256
            || actual.bytes == 0
            || actual.bytes > MAX_FIRMWARE_ARTIFACT_BYTES
        {
            bail!("captured firmware artifact bytes do not match their identity")
        }
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} SHA-256 is invalid")
    }
    Ok(())
}

fn identity(bytes: &[u8]) -> FreshFirmwareBuildFileIdentity {
    FreshFirmwareBuildFileIdentity {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn create_stage(
    root: &Path,
    name: &str,
    captures: &[FreshFirmwareBuildArtifactInput<'_>],
) -> Result<PathBuf> {
    let stage = root.join(name);
    fs::create_dir(&stage)
        .with_context(|| format!("creating private fresh firmware {name} stage"))?;
    for capture in captures {
        let path = stage.join(&capture.identity.path);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .with_context(|| {
                format!("staging fresh firmware artifact {}", capture.identity.path)
            })?;
        file.write_all(capture.contents).with_context(|| {
            format!("staging fresh firmware artifact {}", capture.identity.path)
        })?;
        file.sync_all().with_context(|| {
            format!("syncing fresh firmware artifact {}", capture.identity.path)
        })?;
    }
    if !stage_has_exact_sources(&stage, captures, true) {
        bail!("private fresh firmware stage does not match the captured source closure")
    }
    Ok(stage)
}

fn stage_has_exact_sources(
    stage: &Path,
    captures: &[FreshFirmwareBuildArtifactInput<'_>],
    require_closure: bool,
) -> bool {
    if require_closure {
        let expected = FIRMWARE_ARTIFACTS.into_iter().collect::<BTreeSet<_>>();
        let Ok(entries) = fs::read_dir(stage) else {
            return false;
        };
        let mut actual = BTreeSet::new();
        for entry in entries {
            let Ok(entry) = entry else {
                return false;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                return false;
            };
            actual.insert(name);
        }
        if actual
            != expected
                .into_iter()
                .map(str::to_string)
                .collect::<BTreeSet<_>>()
        {
            return false;
        }
    }
    captures
        .iter()
        .all(|capture| staged_source_matches(stage, capture))
}

fn staged_source_matches(stage: &Path, capture: &FreshFirmwareBuildArtifactInput<'_>) -> bool {
    let path = stage.join(&capture.identity.path);
    let Ok(before) = fs::symlink_metadata(&path) else {
        return false;
    };
    if !before.file_type().is_file() || before.len() != capture.identity.bytes {
        return false;
    }
    let Ok(mut file) = File::open(&path) else {
        return false;
    };
    let Ok(opened) = file.metadata() else {
        return false;
    };
    if !opened.file_type().is_file()
        || opened.len() != capture.identity.bytes
        || !same_file(&before, &opened)
        || !opened_path_matches(&file, &path).is_ok_and(|matches| matches)
    {
        return false;
    }
    let mut bytes = Vec::with_capacity(capture.identity.bytes as usize);
    if Read::take(&mut file, capture.identity.bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() as u64 != capture.identity.bytes
        || bytes != capture.contents
    {
        return false;
    }
    if file.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    let mut compared = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    {
        let mut limited = Read::take(&mut file, capture.identity.bytes.saturating_add(1));
        loop {
            let Ok(read) = limited.read(&mut buffer) else {
                return false;
            };
            if read == 0 {
                break;
            }
            let Some(end) = compared.checked_add(read) else {
                return false;
            };
            if end > capture.contents.len() || buffer[..read] != capture.contents[compared..end] {
                return false;
            }
            compared = end;
        }
    }
    if compared != capture.contents.len() {
        return false;
    }
    let (Ok(opened_after), Ok(path_after)) = (file.metadata(), fs::symlink_metadata(&path)) else {
        return false;
    };
    opened_after.len() == capture.identity.bytes
        && path_after.file_type().is_file()
        && path_after.len() == capture.identity.bytes
        && same_file(&opened, &opened_after)
        && same_file(&opened_after, &path_after)
        && opened_path_matches(&file, &path).is_ok_and(|matches| matches)
}

fn enforce_stage_integrity(
    check: &FreshFirmwareBuildCheck,
    stage: &Path,
    captures: &[FreshFirmwareBuildArtifactInput<'_>],
) -> Result<()> {
    if check.attempted && !stage_has_exact_sources(stage, captures, false) {
        bail!(
            "fresh firmware source stage changed while running {}",
            check.name
        )
    }
    Ok(())
}

fn validate_compiled_output(path: &Path, check: &mut FreshFirmwareBuildCheck) -> Option<PathBuf> {
    let regular = fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_file());
    let canonical = regular.then(|| fs::canonicalize(path)).and_then(Result::ok);
    if canonical.is_none() {
        mark_failed(check, FreshFirmwareBuildFailure::MissingOutput);
    }
    canonical
}

fn python_bytecode_is_present(stage: &Path) -> bool {
    let cache = stage.join("__pycache__");
    let Ok(metadata) = fs::symlink_metadata(&cache) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    let Ok(mut entries) = fs::read_dir(cache) else {
        return false;
    };
    let Some(Ok(entry)) = entries.next() else {
        return false;
    };
    if entries.next().is_some() {
        return false;
    }
    let name = entry.file_name();
    let name = name.to_string_lossy();
    name.starts_with("host.")
        && name.ends_with(".pyc")
        && entry
            .file_type()
            .is_ok_and(|file_type| file_type.is_file() && !file_type.is_symlink())
}

fn run_check(
    name: &str,
    evidence_command: &[String],
    stage: &Path,
    actual_program: Option<&Path>,
    timeout: Duration,
    cancellation: Option<&AtomicBool>,
) -> Result<FreshFirmwareBuildCheck> {
    ensure_not_cancelled(cancellation)?;
    let mut process =
        actual_program.map_or_else(|| Command::new(&evidence_command[0]), Command::new);
    process.args(&evidence_command[1..]).current_dir(stage);
    let limits = ProcessLimits {
        timeout,
        stdout_bytes: FRESH_FIRMWARE_BUILD_STDOUT_BYTES,
        stderr_bytes: FRESH_FIRMWARE_BUILD_STDERR_BYTES,
    };
    let result = match run_bounded(&mut process, limits, cancellation) {
        Ok(output) if output.status.success() => FreshFirmwareBuildCheck {
            name: name.to_string(),
            command: evidence_command.to_vec(),
            attempted: true,
            passed: true,
            exit_code: output.status.code(),
            failure: None,
        },
        Ok(output) => FreshFirmwareBuildCheck {
            name: name.to_string(),
            command: evidence_command.to_vec(),
            attempted: true,
            passed: false,
            exit_code: output.status.code(),
            failure: Some(FreshFirmwareBuildFailure::ExitFailure),
        },
        Err(error) => FreshFirmwareBuildCheck {
            name: name.to_string(),
            command: evidence_command.to_vec(),
            attempted: true,
            passed: false,
            exit_code: None,
            failure: Some(classify_process_error(error)?),
        },
    };
    ensure_not_cancelled(cancellation)?;
    Ok(result)
}

fn classify_process_error(error: ProcessError) -> Result<FreshFirmwareBuildFailure> {
    Ok(match error {
        ProcessError::Cancelled => bail!("fresh firmware bundle build cancelled"),
        ProcessError::InvalidTimeout { .. } => {
            bail!("fresh firmware bounded-process timeout invariant failed")
        }
        ProcessError::Wait(_) => {
            bail!("fresh firmware child could not be safely reaped")
        }
        ProcessError::Spawn(_) => FreshFirmwareBuildFailure::SpawnFailure,
        ProcessError::Timeout { .. } => FreshFirmwareBuildFailure::Timeout,
        ProcessError::StdoutLimit { .. } => FreshFirmwareBuildFailure::StdoutLimit,
        ProcessError::StderrLimit { .. } => FreshFirmwareBuildFailure::StderrLimit,
        ProcessError::PostSpawnSetup(_) | ProcessError::Read { .. } => {
            FreshFirmwareBuildFailure::SupervisionFailure
        }
    })
}

fn dependency_check(name: &str, command: Vec<String>) -> FreshFirmwareBuildCheck {
    FreshFirmwareBuildCheck {
        name: name.to_string(),
        command,
        attempted: false,
        passed: false,
        exit_code: None,
        failure: Some(FreshFirmwareBuildFailure::DependencyFailed),
    }
}

fn mark_failed(check: &mut FreshFirmwareBuildCheck, failure: FreshFirmwareBuildFailure) {
    check.passed = false;
    check.failure = Some(failure);
}

fn c_compile_command(tool: &str) -> Vec<String> {
    [
        tool,
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-I",
        ".",
        "firmware.c",
        "firmware_smoke_test.c",
        "-o",
        C_OUTPUT,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn cpp_compile_command(tool: &str) -> Vec<String> {
    [
        tool,
        "-std=c++17",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-pedantic",
        "-I",
        ".",
        "firmware.cpp",
        "firmware_cpp_smoke_test.cpp",
        "-o",
        CPP_OUTPUT,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn c_smoke_command() -> Vec<String> {
    vec![smoke_command(C_OUTPUT)]
}

fn cpp_smoke_command() -> Vec<String> {
    vec![smoke_command(CPP_OUTPUT)]
}

fn python_compile_command(tool: &str) -> Vec<String> {
    [tool, "-m", "py_compile", "host.py"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn python_self_test_command(tool: &str) -> Vec<String> {
    [tool, "host.py", "--self-test"]
        .into_iter()
        .map(str::to_string)
        .collect()
}

fn smoke_command(output: &str) -> String {
    #[cfg(windows)]
    {
        format!(r".\{output}")
    }
    #[cfg(not(windows))]
    {
        format!("./{output}")
    }
}

/// Validate every closed-report invariant independently of construction.
pub(crate) fn validate_fresh_firmware_build_report(
    report: &FreshFirmwareBuildReport,
) -> Result<()> {
    if report.schema_version != FRESH_FIRMWARE_BUILD_REPORT_SCHEMA_VERSION
        || report.scope != FRESH_FIRMWARE_BUILD_SCOPE
        || report.engine_version != env!("CARGO_PKG_VERSION")
    {
        bail!("fresh firmware build report version, scope, or engine is invalid")
    }
    if report.bundle.manifest_schema_version != FIRMWARE_SCHEMA_VERSION
        || report.bundle.manifest.bytes == 0
        || report.bundle.manifest.bytes > FRESH_FIRMWARE_BUILD_MAX_MANIFEST_BYTES as u64
    {
        bail!("fresh firmware build report manifest identity is invalid")
    }
    validate_sha256(&report.bundle.manifest.sha256, "fresh firmware manifest")?;
    validate_sha256(&report.bundle.schematic_sha256, "fresh firmware schematic")?;
    validate_artifact_descriptors(&report.bundle.artifacts)?;
    if report.process_limits.timeout_seconds == 0
        || report.process_limits.timeout_seconds > MAX_TIMEOUT_SECONDS
        || report.process_limits.stdout_bytes != FRESH_FIRMWARE_BUILD_STDOUT_BYTES
        || report.process_limits.stderr_bytes != FRESH_FIRMWARE_BUILD_STDERR_BYTES
    {
        bail!("fresh firmware build report process limits are invalid")
    }
    if report.checks.len() != CHECK_NAMES.len() {
        bail!("fresh firmware build report must contain exactly six checks")
    }
    for (index, (check, expected_name)) in report.checks.iter().zip(CHECK_NAMES).enumerate() {
        if check.name != expected_name {
            bail!("fresh firmware build report check order or name is invalid")
        }
        validate_check_state(check)?;
        if index % 2 == 0 && !check.attempted {
            bail!("fresh firmware build report compile checks must be attempted")
        }
        if index % 2 == 1 && check.failure == Some(FreshFirmwareBuildFailure::MissingOutput) {
            bail!("fresh firmware build report smoke checks cannot report missing output")
        }
    }
    validate_report_commands(&report.checks)?;
    for (compile, smoke) in [(0, 1), (2, 3), (4, 5)] {
        let compile = &report.checks[compile];
        let smoke = &report.checks[smoke];
        if compile.passed {
            if !smoke.attempted
                || smoke.failure == Some(FreshFirmwareBuildFailure::DependencyFailed)
            {
                bail!("fresh firmware build report smoke dependency state is invalid")
            }
        } else if smoke.attempted
            || smoke.failure != Some(FreshFirmwareBuildFailure::DependencyFailed)
        {
            bail!("fresh firmware build report failed compile did not dependency-skip smoke")
        }
    }
    let approved = report.checks.iter().all(|check| check.passed);
    if report.approved != approved || report.toolchain_provenance_verified {
        bail!("fresh firmware build report approval or provenance invariant is invalid")
    }
    Ok(())
}

fn validate_check_state(check: &FreshFirmwareBuildCheck) -> Result<()> {
    let valid = match check.failure {
        None => check.attempted && check.passed && check.exit_code == Some(0),
        Some(FreshFirmwareBuildFailure::DependencyFailed) => {
            !check.attempted && !check.passed && check.exit_code.is_none()
        }
        Some(FreshFirmwareBuildFailure::ExitFailure) => {
            check.attempted && !check.passed && check.exit_code != Some(0)
        }
        Some(FreshFirmwareBuildFailure::MissingOutput) => {
            check.attempted && !check.passed && check.exit_code == Some(0)
        }
        Some(
            FreshFirmwareBuildFailure::SpawnFailure
            | FreshFirmwareBuildFailure::Timeout
            | FreshFirmwareBuildFailure::StdoutLimit
            | FreshFirmwareBuildFailure::StderrLimit,
        ) => check.attempted && !check.passed && check.exit_code.is_none(),
        Some(FreshFirmwareBuildFailure::SupervisionFailure) => {
            check.attempted && !check.passed && check.exit_code.is_none()
        }
    };
    if !valid {
        bail!("fresh firmware build report check state is invalid")
    }
    Ok(())
}

fn validate_report_commands(checks: &[FreshFirmwareBuildCheck]) -> Result<()> {
    let cc = checks[0]
        .command
        .first()
        .ok_or_else(|| anyhow!("fresh firmware C command is empty"))?;
    let cxx = checks[2]
        .command
        .first()
        .ok_or_else(|| anyhow!("fresh firmware C++ command is empty"))?;
    let python = checks[4]
        .command
        .first()
        .ok_or_else(|| anyhow!("fresh firmware Python command is empty"))?;
    validate_tool_name(cc, "fresh firmware report C compiler")?;
    validate_tool_name(cxx, "fresh firmware report C++ compiler")?;
    validate_tool_name(python, "fresh firmware report Python interpreter")?;
    let expected = [
        c_compile_command(cc),
        c_smoke_command(),
        cpp_compile_command(cxx),
        cpp_smoke_command(),
        python_compile_command(python),
        python_self_test_command(python),
    ];
    if checks
        .iter()
        .zip(expected)
        .any(|(check, command)| check.command != command)
    {
        bail!("fresh firmware build report contains a non-fixed command")
    }
    Ok(())
}

/// Pretty-print a validated report with exactly one trailing LF.
pub(crate) fn render_fresh_firmware_build_report(
    report: &FreshFirmwareBuildReport,
) -> Result<Vec<u8>> {
    validate_fresh_firmware_build_report(report)?;
    let mut bytes =
        serde_json::to_vec_pretty(report).context("serializing fresh firmware build report")?;
    bytes.push(b'\n');
    if bytes.len() > FRESH_FIRMWARE_BUILD_MAX_REPORT_BYTES {
        bail!("fresh firmware build report exceeds {FRESH_FIRMWARE_BUILD_MAX_REPORT_BYTES} bytes")
    }
    Ok(bytes)
}

/// Strictly decode canonical retained report bytes.
#[allow(dead_code)]
pub(crate) fn decode_fresh_firmware_build_report(bytes: &[u8]) -> Result<FreshFirmwareBuildReport> {
    if bytes.is_empty() || bytes.len() > FRESH_FIRMWARE_BUILD_MAX_REPORT_BYTES {
        bail!("fresh firmware build report byte count is invalid")
    }
    reject_duplicate_json_keys(bytes).context("decoding fresh firmware build report")?;
    let report: FreshFirmwareBuildReport =
        serde_json::from_slice(bytes).context("decoding fresh firmware build report")?;
    if render_fresh_firmware_build_report(&report)? != bytes {
        bail!("fresh firmware build report is not canonical pretty JSON")
    }
    Ok(report)
}

/// Closed JSON Schema Draft 2020-12 for fresh build evidence.
pub(crate) fn fresh_firmware_build_report_schema() -> Value {
    let artifact_prefixes = FIRMWARE_ARTIFACTS
        .into_iter()
        .map(|path| {
            json!({
                "allOf": [
                    {"$ref": "#/$defs/artifact"},
                    {"properties": {"path": {"const": path}}, "required": ["path"]}
                ]
            })
        })
        .collect::<Vec<_>>();
    let check_prefixes = [
        check_prefix(
            CHECK_NAMES[0],
            command_schema(&c_compile_command("TOOL"), true),
        ),
        check_prefix(CHECK_NAMES[1], command_schema(&c_smoke_command(), false)),
        check_prefix(
            CHECK_NAMES[2],
            command_schema(&cpp_compile_command("TOOL"), true),
        ),
        check_prefix(CHECK_NAMES[3], command_schema(&cpp_smoke_command(), false)),
        check_prefix(
            CHECK_NAMES[4],
            command_schema(&python_compile_command("TOOL"), true),
        ),
        check_prefix(
            CHECK_NAMES[5],
            command_schema(&python_self_test_command("TOOL"), true),
        ),
    ];
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/fresh-firmware-bundle-build-v1.json",
        "title": "pcbex fresh firmware bundle build evidence",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "scope", "engine_version", "bundle", "process_limits",
            "checks", "toolchain_provenance_verified", "approved"
        ],
        "properties": {
            "schema_version": {"const": FRESH_FIRMWARE_BUILD_REPORT_SCHEMA_VERSION},
            "scope": {"const": FRESH_FIRMWARE_BUILD_SCOPE},
            "engine_version": {
                "const": env!("CARGO_PKG_VERSION")
            },
            "bundle": {
                "type": "object", "additionalProperties": false,
                "required": ["manifest", "manifest_schema_version", "schematic_sha256", "artifacts"],
                "properties": {
                    "manifest": {"$ref": "#/$defs/manifest_identity"},
                    "manifest_schema_version": {"const": FIRMWARE_SCHEMA_VERSION},
                    "schematic_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "artifacts": {
                        "type": "array", "minItems": FIRMWARE_ARTIFACTS.len(),
                        "maxItems": FIRMWARE_ARTIFACTS.len(),
                        "prefixItems": artifact_prefixes, "items": false
                    }
                }
            },
            "process_limits": {
                "type": "object", "additionalProperties": false,
                "required": ["timeout_seconds", "stdout_bytes", "stderr_bytes"],
                "properties": {
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECONDS},
                    "stdout_bytes": {"const": FRESH_FIRMWARE_BUILD_STDOUT_BYTES},
                    "stderr_bytes": {"const": FRESH_FIRMWARE_BUILD_STDERR_BYTES}
                }
            },
            "checks": {
                "type": "array", "minItems": CHECK_NAMES.len(), "maxItems": CHECK_NAMES.len(),
                "prefixItems": check_prefixes, "items": false
            },
            "toolchain_provenance_verified": {"const": false},
            "approved": {"type": "boolean"}
        },
        "$defs": {
            "manifest_identity": {
                "type": "object", "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1, "maximum": FRESH_FIRMWARE_BUILD_MAX_MANIFEST_BYTES},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "artifact": {
                "type": "object", "additionalProperties": false,
                "required": ["path", "bytes", "sha256"],
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_FIRMWARE_ARTIFACT_BYTES},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "check": {
                "type": "object", "additionalProperties": false,
                "required": ["name", "command", "attempted", "passed", "exit_code", "failure"],
                "properties": {
                    "name": {"type": "string", "enum": CHECK_NAMES},
                    "command": {
                        "type": "array", "minItems": 1, "maxItems": MAX_COMMAND_ARGUMENTS,
                        "items": {"type": "string", "minLength": 1, "maxLength": MAX_COMMAND_TEXT, "pattern": COMMAND_TEXT_PATTERN}
                    },
                    "attempted": {"type": "boolean"},
                    "passed": {"type": "boolean"},
                    "exit_code": {"type": ["integer", "null"], "minimum": i32::MIN, "maximum": i32::MAX},
                    "failure": {"type": ["string", "null"], "enum": [
                        null, "dependency_failed", "exit_failure", "missing_output", "spawn_failure",
                        "timeout", "stdout_limit", "stderr_limit", "supervision_failure"
                    ]}
                },
                "oneOf": check_state_schemas()
            }
        }
    })
}

fn check_prefix(name: &str, command: Value) -> Value {
    json!({
        "allOf": [
            {"$ref": "#/$defs/check"},
            {"properties": {"name": {"const": name}, "command": command}, "required": ["name", "command"]}
        ]
    })
}

fn command_schema(command: &[String], dynamic_first: bool) -> Value {
    let prefix = command
        .iter()
        .enumerate()
        .map(|(index, argument)| {
            if dynamic_first && index == 0 {
                json!({
                    "type": "string", "minLength": 1, "maxLength": MAX_COMMAND_TEXT,
                    "pattern": COMMAND_TEXT_PATTERN, "not": {"enum": [".", ".."]}
                })
            } else {
                json!({"const": argument})
            }
        })
        .collect::<Vec<_>>();
    json!({
        "type": "array", "minItems": command.len(), "maxItems": command.len(),
        "prefixItems": prefix, "items": false
    })
}

fn check_state_schemas() -> Vec<Value> {
    vec![
        json!({"properties": {"attempted": {"const": true}, "passed": {"const": true}, "exit_code": {"const": 0}, "failure": {"type": "null"}}, "required": ["attempted", "passed", "exit_code", "failure"]}),
        json!({"properties": {"attempted": {"const": false}, "passed": {"const": false}, "exit_code": {"type": "null"}, "failure": {"const": "dependency_failed"}}, "required": ["attempted", "passed", "exit_code", "failure"]}),
        json!({"properties": {"attempted": {"const": true}, "passed": {"const": false}, "exit_code": {"not": {"const": 0}}, "failure": {"const": "exit_failure"}}, "required": ["attempted", "passed", "exit_code", "failure"]}),
        json!({"properties": {"attempted": {"const": true}, "passed": {"const": false}, "exit_code": {"const": 0}, "failure": {"const": "missing_output"}}, "required": ["attempted", "passed", "exit_code", "failure"]}),
        json!({"properties": {"attempted": {"const": true}, "passed": {"const": false}, "exit_code": {"type": "null"}, "failure": {"enum": ["spawn_failure", "timeout", "stdout_limit", "stderr_limit"]}}, "required": ["attempted", "passed", "exit_code", "failure"]}),
        json!({"properties": {"attempted": {"const": true}, "passed": {"const": false}, "exit_code": {"type": "null"}, "failure": {"const": "supervision_failure"}}, "required": ["attempted", "passed", "exit_code", "failure"]}),
    ]
}

fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<()> {
    use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
    use std::fmt;

    struct Seed;
    struct AnyVisitor;

    impl<'de> DeserializeSeed<'de> for Seed {
        type Value = ();

        fn deserialize<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
        where
            D: Deserializer<'de>,
        {
            deserializer.deserialize_any(AnyVisitor)
        }
    }

    impl<'de> Visitor<'de> for AnyVisitor {
        type Value = ();

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a JSON value without duplicate object keys")
        }

        fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_string<E>(self, _: String) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_none<E>(self) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> std::result::Result<(), E> {
            Ok(())
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
        where
            A: SeqAccess<'de>,
        {
            while sequence.next_element_seed(Seed)?.is_some() {}
            Ok(())
        }

        fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut keys = BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key) {
                    return Err(serde::de::Error::custom("duplicate JSON object key"));
                }
                map.next_value_seed(Seed)?;
            }
            Ok(())
        }
    }

    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    Seed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firmware::FirmwareCommandEvidence;
    use std::io;

    struct Fixture {
        manifest: Vec<u8>,
        identities: Vec<FirmwareArtifact>,
        sources: Vec<Vec<u8>>,
    }

    fn fixture() -> Fixture {
        let sources = vec![
            b"#ifndef PINOUT_H\n#define PINOUT_H\n#define TEST_PIN 1\n#endif\n".to_vec(),
            b"#ifndef FIRMWARE_H\n#define FIRMWARE_H\n#ifdef __cplusplus\nextern \"C\" {\n#endif\nint firmware_value(void);\n#ifdef __cplusplus\n}\n#endif\n#endif\n".to_vec(),
            b"#include \"firmware.h\"\nint firmware_value(void) { return 1; }\n".to_vec(),
            b"#include \"pinout.h\"\n#include \"firmware.h\"\n#ifndef TEST_VALUE\n#define TEST_VALUE 1\n#endif\nint main(void) { return firmware_value() == 1 ? 0 : 1; }\n".to_vec(),
            b"#include \"firmware.h\"\nextern \"C\" int firmware_value(void) { return 2; }\n".to_vec(),
            b"#include \"pinout.h\"\n#include \"firmware.h\"\nint main() { return firmware_value() == 2 ? 0 : 1; }\n".to_vec(),
            b"import sys\ndef main():\n    return 0 if sys.argv[1:] == ['--self-test'] else 1\nif __name__ == '__main__':\n    raise SystemExit(main())\n".to_vec(),
        ];
        let identities = FIRMWARE_ARTIFACTS
            .iter()
            .zip(&sources)
            .map(|(path, bytes)| FirmwareArtifact {
                path: (*path).to_string(),
                bytes: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(bytes)),
            })
            .collect::<Vec<_>>();
        let passed = |command: Vec<String>| FirmwareCommandEvidence {
            attempted: true,
            passed: true,
            command,
            exit_code: Some(0),
        };
        let manifest = FirmwareManifest {
            schema_version: FIRMWARE_SCHEMA_VERSION,
            engine: "pcbex".to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            schematic_sha256: "a".repeat(64),
            artifacts: identities.clone(),
            c_build: FirmwareBuildEvidence {
                attempted: true,
                passed: true,
                command: vec!["forged-c-command".to_string()],
                exit_code: Some(0),
                smoke: passed(vec!["forged-c-smoke".to_string()]),
            },
            cpp_build: FirmwareBuildEvidence {
                attempted: true,
                passed: true,
                command: vec!["forged-cpp-command".to_string()],
                exit_code: Some(0),
                smoke: passed(vec!["forged-cpp-smoke".to_string()]),
            },
            python_check: FirmwareBuildEvidence {
                attempted: true,
                passed: true,
                command: vec!["forged-python-command".to_string()],
                exit_code: Some(0),
                smoke: passed(vec!["forged-python-smoke".to_string()]),
            },
        };
        Fixture {
            manifest: serde_json::to_vec_pretty(&manifest).unwrap(),
            identities,
            sources,
        }
    }

    fn with_input<T>(
        fixture: &Fixture,
        operation: impl FnOnce(FreshFirmwareBuildInput<'_>) -> T,
    ) -> T {
        let captures = fixture
            .identities
            .iter()
            .zip(&fixture.sources)
            .map(|(identity, contents)| FreshFirmwareBuildArtifactInput { identity, contents })
            .collect::<Vec<_>>();
        operation(FreshFirmwareBuildInput {
            manifest_bytes: &fixture.manifest,
            artifacts: &captures,
        })
    }

    #[test]
    fn real_fresh_checks_pass_and_manifest_commands_are_ignored() {
        let fixture = fixture();
        let report = with_input(&fixture, |input| {
            verify_fresh_firmware_bundle_build(
                input,
                FreshFirmwareBuildOptions {
                    timeout: Duration::from_secs(10),
                    ..FreshFirmwareBuildOptions::default()
                },
                None,
            )
            .unwrap()
        });
        assert!(report.approved);
        assert!(report.checks.iter().all(|check| check.passed));
        assert_eq!(report.checks[0].command, c_compile_command("cc"));
        assert!(
            !report.checks[0]
                .command
                .iter()
                .any(|arg| arg.contains("forged"))
        );
        let rendered = render_fresh_firmware_build_report(&report).unwrap();
        assert_eq!(rendered.last(), Some(&b'\n'));
        assert!(rendered.len() <= FRESH_FIRMWARE_BUILD_MAX_REPORT_BYTES);
        assert_eq!(
            decode_fresh_firmware_build_report(&rendered).unwrap(),
            report
        );
    }

    #[cfg(unix)]
    #[test]
    fn successful_process_without_compile_outputs_is_typed_rejection() {
        let fixture = fixture();
        let report = with_input(&fixture, |input| {
            verify_fresh_firmware_bundle_build(
                input,
                FreshFirmwareBuildOptions {
                    cc: "true",
                    cxx: "true",
                    python: "true",
                    timeout: Duration::from_secs(2),
                },
                None,
            )
            .unwrap()
        });
        assert!(!report.approved);
        for index in [0, 2, 4] {
            assert_eq!(
                report.checks[index].failure,
                Some(FreshFirmwareBuildFailure::MissingOutput)
            );
            assert_eq!(report.checks[index].exit_code, Some(0));
            assert_eq!(
                report.checks[index + 1].failure,
                Some(FreshFirmwareBuildFailure::DependencyFailed)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn child_source_mutation_is_a_hard_error() {
        let fixture = fixture();
        let captures = fixture
            .identities
            .iter()
            .zip(&fixture.sources)
            .map(|(identity, contents)| FreshFirmwareBuildArtifactInput { identity, contents })
            .collect::<Vec<_>>();
        let root = tempfile::tempdir().unwrap();
        let stage = create_stage(root.path(), "mutation", &captures).unwrap();
        let command = vec![
            "ignored-evidence-program".to_string(),
            "-c".to_string(),
            "printf mutation >> firmware.cpp".to_string(),
        ];
        let check = run_check(
            "mutation_test",
            &command,
            &stage,
            Some(Path::new("/bin/sh")),
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        assert!(check.passed);
        let error = enforce_stage_integrity(&check, &stage, &captures).unwrap_err();
        assert!(format!("{error:#}").contains("source stage changed"));
    }

    #[test]
    fn spawn_failures_are_retained_and_cancellation_is_hard_error() {
        let fixture = fixture();
        let options = FreshFirmwareBuildOptions {
            cc: "pcbex-no-such-cc",
            cxx: "pcbex-no-such-cxx",
            python: "pcbex-no-such-python",
            timeout: Duration::from_secs(2),
        };
        let report = with_input(&fixture, |input| {
            verify_fresh_firmware_bundle_build(input, options, None).unwrap()
        });
        assert!(!report.approved);
        for index in [0, 2, 4] {
            assert_eq!(
                report.checks[index].failure,
                Some(FreshFirmwareBuildFailure::SpawnFailure)
            );
            assert_eq!(
                report.checks[index + 1].failure,
                Some(FreshFirmwareBuildFailure::DependencyFailed)
            );
        }
        let cancelled = AtomicBool::new(true);
        let error = with_input(&fixture, |input| {
            verify_fresh_firmware_bundle_build(input, options, Some(&cancelled)).unwrap_err()
        });
        assert!(format!("{error:#}").contains("cancelled"));
    }

    #[test]
    fn rejects_identity_order_and_duplicate_keys_but_accepts_non_pretty_json() {
        let mut wrong_order = fixture();
        wrong_order.identities.swap(0, 1);
        assert!(
            with_input(&wrong_order, |input| {
                verify_fresh_firmware_bundle_build(
                    input,
                    FreshFirmwareBuildOptions::default(),
                    None,
                )
            })
            .is_err()
        );

        let base_fixture = fixture();
        let duplicated = base_fixture
            .manifest
            .iter()
            .position(|byte| *byte == b'{')
            .map(|position| {
                let mut bytes = base_fixture.manifest.clone();
                bytes.splice(
                    position + 1..position + 1,
                    b"\"schema_version\":2,".iter().copied(),
                );
                bytes
            })
            .unwrap();
        let mut altered = fixture();
        altered.manifest = duplicated;
        assert!(
            with_input(&altered, |input| {
                verify_fresh_firmware_bundle_build(
                    input,
                    FreshFirmwareBuildOptions::default(),
                    None,
                )
            })
            .is_err()
        );

        let mut altered = fixture();
        let manifest: FirmwareManifest = serde_json::from_slice(&altered.manifest).unwrap();
        altered.manifest = serde_json::to_vec(&manifest).unwrap();
        let report = with_input(&altered, |input| {
            verify_fresh_firmware_bundle_build(
                input,
                FreshFirmwareBuildOptions {
                    cc: "pcbex-no-such-cc",
                    cxx: "pcbex-no-such-cxx",
                    python: "pcbex-no-such-python",
                    timeout: Duration::from_secs(1),
                },
                None,
            )
            .unwrap()
        });
        assert_eq!(report.bundle.manifest, identity(&altered.manifest));
    }

    #[test]
    fn accepts_valid_v2_aggregate_failure_after_successful_compile() {
        let mut fixture = fixture();
        let mut manifest: FirmwareManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        manifest.c_build.passed = false;
        manifest.c_build.smoke.passed = false;
        manifest.c_build.smoke.exit_code = Some(7);
        fixture.manifest = serde_json::to_vec(&manifest).unwrap();
        let report = with_input(&fixture, |input| {
            verify_fresh_firmware_bundle_build(
                input,
                FreshFirmwareBuildOptions {
                    cc: "pcbex-no-such-cc",
                    cxx: "pcbex-no-such-cxx",
                    python: "pcbex-no-such-python",
                    timeout: Duration::from_secs(1),
                },
                None,
            )
            .unwrap()
        });
        assert_eq!(
            report.checks[0].failure,
            Some(FreshFirmwareBuildFailure::SpawnFailure)
        );
    }

    #[test]
    fn process_failures_have_exact_mapping() {
        assert_eq!(
            classify_process_error(ProcessError::Spawn(io::Error::other("spawn"))).unwrap(),
            FreshFirmwareBuildFailure::SpawnFailure,
        );
        assert_eq!(
            classify_process_error(ProcessError::Timeout {
                timeout: Duration::from_secs(1)
            })
            .unwrap(),
            FreshFirmwareBuildFailure::Timeout,
        );
        assert_eq!(
            classify_process_error(ProcessError::StdoutLimit { limit: 1 }).unwrap(),
            FreshFirmwareBuildFailure::StdoutLimit,
        );
        assert_eq!(
            classify_process_error(ProcessError::StderrLimit { limit: 1 }).unwrap(),
            FreshFirmwareBuildFailure::StderrLimit,
        );
        assert_eq!(
            classify_process_error(ProcessError::Read {
                stream: crate::bounded_process::ProcessStream::Stdout,
                source: io::Error::other("read"),
            })
            .unwrap(),
            FreshFirmwareBuildFailure::SupervisionFailure,
        );
        assert!(classify_process_error(ProcessError::Wait(io::Error::other("wait"))).is_err());
        assert!(classify_process_error(ProcessError::Cancelled).is_err());
    }

    #[test]
    fn report_schema_and_runtime_invariants_are_closed() {
        let schema = fresh_firmware_build_report_schema();
        assert_eq!(
            schema["$schema"],
            "https://json-schema.org/draft/2020-12/schema"
        );
        assert_eq!(schema["additionalProperties"], false);
        assert_eq!(
            schema["properties"]["bundle"]["additionalProperties"],
            false
        );
        assert_eq!(schema["properties"]["checks"]["items"], false);
        assert_eq!(
            schema["properties"]["checks"]["prefixItems"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        assert_eq!(
            schema["properties"]["bundle"]["properties"]["artifacts"]["items"],
            false
        );
        let failures = schema["$defs"]["check"]["properties"]["failure"]["enum"]
            .as_array()
            .unwrap();
        assert_eq!(failures.len(), 9);

        let fixture = fixture();
        let mut report = with_input(&fixture, |input| {
            verify_fresh_firmware_bundle_build(
                input,
                FreshFirmwareBuildOptions {
                    cc: "pcbex-no-such-cc",
                    cxx: "pcbex-no-such-cxx",
                    python: "pcbex-no-such-python",
                    timeout: Duration::from_secs(1),
                },
                None,
            )
            .unwrap()
        });
        report.approved = true;
        assert!(validate_fresh_firmware_build_report(&report).is_err());
        report.approved = false;
        report.toolchain_provenance_verified = true;
        assert!(validate_fresh_firmware_build_report(&report).is_err());

        report.toolchain_provenance_verified = false;
        report.checks[0].attempted = false;
        report.checks[0].passed = false;
        report.checks[0].exit_code = None;
        report.checks[0].failure = Some(FreshFirmwareBuildFailure::DependencyFailed);
        assert!(validate_fresh_firmware_build_report(&report).is_err());

        report.checks[0].attempted = true;
        report.checks[0].passed = true;
        report.checks[0].exit_code = Some(0);
        report.checks[0].failure = None;
        report.checks[1].attempted = true;
        report.checks[1].passed = false;
        report.checks[1].exit_code = Some(0);
        report.checks[1].failure = Some(FreshFirmwareBuildFailure::MissingOutput);
        assert!(validate_fresh_firmware_build_report(&report).is_err());
    }
}
