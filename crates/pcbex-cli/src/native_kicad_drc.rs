//! Bounded, deterministic native KiCad PCB DRC evidence.
//!
//! The KiCad DRC report contains a few values which are deliberately not
//! suitable as evidence identities: its timestamp and, for legacy boards,
//! generated item UUIDs.  This module stages every input in a private
//! directory, runs the fixed KiCad command under the shared process bounds,
//! and publishes a normalized report which excludes both values.  A retained
//! report can consequently be replayed and compared byte-for-byte.

use anyhow::{Context, Result, bail};
use serde::de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Maximum raw or rendered native PCB DRC report size.
pub(crate) const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;

const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_VERSION_BYTES: usize = 256;
const MAX_UUID_BYTES: usize = 128;
const MAX_IGNORED_CHECKS: usize = 1024;
const MAX_FINDINGS: usize = 100_000;
const MAX_ITEMS_PER_FINDING: usize = 1024;
const MAX_COORDINATE_MM: f64 = 1_000_000_000.0;
const NANOMETRES_PER_MM: f64 = 1_000_000.0;
const KICAD_DRC_TIMEOUT: Duration = Duration::from_secs(600);
const KICAD_DRC_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const KICAD_DRC_STDERR_BYTES: usize = 1024 * 1024;
const NATIVE_DRC_DOMAIN: &[u8] = b"pcbex/native-kicad-pcb-drc/v1\0";
const STAGED_INPUT_NAME: &str = "input.kicad_pcb";
const STAGED_PROJECT_NAME: &str = "input.kicad_pro";
const STAGED_RULES_NAME: &str = "input.kicad_dru";
const STAGED_REPORT_NAME: &str = "drc.json";
const DRC_SCHEMA: &str = "https://schemas.kicad.org/drc.v1.json";

/// A bounded identity of one source file.  Paths are intentionally omitted:
/// the bytes, not an operational path, are what the evidence binds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcSourceIdentity {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcInvocation {
    pub command: String,
    pub format: String,
    pub units: String,
    pub severities: Vec<String>,
    pub exit_code_violations: bool,
    pub all_track_errors: bool,
    pub schematic_parity: bool,
    pub refill_zones: bool,
    pub save_board: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcIgnoredCheck {
    pub description: String,
    pub key: String,
}

/// A position quantized to KiCad DRC's millimetre output precision (nm).
/// Quantization makes the normalized report independent of insignificant
/// floating-point formatting differences while preserving the two-dimensional
/// location needed to review a finding.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcPosition {
    pub x: i64,
    pub y: i64,
}

/// A normalized DRC item intentionally containing only description and
/// position.  KiCad's raw UUID is validated but excluded because it may be
/// regenerated for a legacy board on every run.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcItem {
    pub description: String,
    pub position_nm: NativeKicadDrcPosition,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcFinding {
    pub category: String,
    pub description: String,
    pub items: Vec<NativeKicadDrcItem>,
    pub severity: String,
    #[serde(rename = "type")]
    pub finding_type: String,
}

/// Closed and deterministic native KiCad PCB DRC evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadDrcReport {
    pub schema_version: u32,
    pub engine: String,
    pub engine_version: String,
    pub kicad_version: String,
    pub source: NativeKicadDrcSourceIdentity,
    #[serde(default)]
    pub project: Option<NativeKicadDrcSourceIdentity>,
    #[serde(default)]
    pub rules_file: Option<NativeKicadDrcSourceIdentity>,
    pub invocation: NativeKicadDrcInvocation,
    pub ignored_checks: Vec<NativeKicadDrcIgnoredCheck>,
    pub findings: Vec<NativeKicadDrcFinding>,
    pub violation_count: usize,
    pub unconnected_item_count: usize,
    pub schematic_parity_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub approved: bool,
    pub run_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReport {
    #[serde(rename = "$schema")]
    schema: String,
    coordinate_units: String,
    // KiCad writes a timestamp, but it is intentionally discarded.
    date: String,
    #[serde(default)]
    ignored_checks: Vec<RawIgnoredCheck>,
    included_severities: Vec<String>,
    kicad_version: String,
    schematic_parity: Vec<RawFinding>,
    source: String,
    unconnected_items: Vec<RawFinding>,
    violations: Vec<RawFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIgnoredCheck {
    description: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFinding {
    description: String,
    items: Vec<RawItem>,
    severity: String,
    #[serde(rename = "type")]
    finding_type: String,
    #[serde(default)]
    excluded: bool,
    #[serde(default)]
    comment: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawItem {
    description: String,
    pos: RawPosition,
    uuid: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPosition {
    x: f64,
    y: f64,
}

#[derive(Serialize)]
struct RunIdentity<'a> {
    schema_version: u32,
    engine: &'a str,
    engine_version: &'a str,
    kicad_version: &'a str,
    source: &'a NativeKicadDrcSourceIdentity,
    project: &'a Option<NativeKicadDrcSourceIdentity>,
    rules_file: &'a Option<NativeKicadDrcSourceIdentity>,
    invocation: &'a NativeKicadDrcInvocation,
    ignored_checks: &'a [NativeKicadDrcIgnoredCheck],
    findings: &'a [NativeKicadDrcFinding],
    violation_count: usize,
    unconnected_item_count: usize,
    schematic_parity_count: usize,
    error_count: usize,
    warning_count: usize,
    approved: bool,
}

fn report_identity(report: &NativeKicadDrcReport) -> Result<String> {
    let identity = RunIdentity {
        schema_version: report.schema_version,
        engine: &report.engine,
        engine_version: &report.engine_version,
        kicad_version: &report.kicad_version,
        source: &report.source,
        project: &report.project,
        rules_file: &report.rules_file,
        invocation: &report.invocation,
        ignored_checks: &report.ignored_checks,
        findings: &report.findings,
        violation_count: report.violation_count,
        unconnected_item_count: report.unconnected_item_count,
        schematic_parity_count: report.schematic_parity_count,
        error_count: report.error_count,
        warning_count: report.warning_count,
        approved: report.approved,
    };
    let canonical =
        serde_json::to_vec(&identity).context("serializing native KiCad PCB DRC run identity")?;
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_DRC_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn bounded_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.bytes().any(|byte| byte == 0) {
        bail!("native KiCad PCB DRC {label} must contain 1..={max_bytes} non-NUL bytes")
    }
    Ok(())
}

fn bounded_version(value: &str) -> Result<()> {
    bounded_text(value, "version", MAX_VERSION_BYTES)
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("native KiCad PCB DRC {label} must be 64 lowercase hexadecimal characters")
    }
    Ok(())
}

fn source_identity(bytes: &[u8]) -> NativeKicadDrcSourceIdentity {
    NativeKicadDrcSourceIdentity {
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn validate_uuid(value: &str) -> Result<()> {
    if value.len() > MAX_UUID_BYTES || value.len() != 36 {
        bail!("native KiCad PCB DRC item UUID length is invalid")
    }
    for (index, byte) in value.bytes().enumerate() {
        let separator = matches!(index, 8 | 13 | 18 | 23);
        if separator {
            if byte != b'-' {
                bail!("native KiCad PCB DRC item UUID format is invalid")
            }
        } else if !byte.is_ascii_hexdigit() {
            bail!("native KiCad PCB DRC item UUID format is invalid")
        }
    }
    Ok(())
}

fn position_nm(position: &RawPosition) -> Result<NativeKicadDrcPosition> {
    if !position.x.is_finite()
        || !position.y.is_finite()
        || position.x.abs() > MAX_COORDINATE_MM
        || position.y.abs() > MAX_COORDINATE_MM
    {
        bail!("native KiCad PCB DRC item position is not finite or bounded")
    }
    fn quantize(value: f64) -> Result<i64> {
        let scaled = value * NANOMETRES_PER_MM;
        if !scaled.is_finite() || scaled.abs() > i64::MAX as f64 {
            bail!("native KiCad PCB DRC item position exceeds nanometre bounds")
        }
        let rounded = scaled.round();
        if rounded < i64::MIN as f64 || rounded > i64::MAX as f64 {
            bail!("native KiCad PCB DRC item position exceeds nanometre bounds")
        }
        Ok(rounded as i64)
    }
    Ok(NativeKicadDrcPosition {
        x: quantize(position.x)?,
        y: quantize(position.y)?,
    })
}

fn item_cmp(left: &NativeKicadDrcItem, right: &NativeKicadDrcItem) -> Ordering {
    left.description
        .cmp(&right.description)
        .then_with(|| left.position_nm.x.cmp(&right.position_nm.x))
        .then_with(|| left.position_nm.y.cmp(&right.position_nm.y))
}

fn finding_cmp(left: &NativeKicadDrcFinding, right: &NativeKicadDrcFinding) -> Ordering {
    left.category
        .cmp(&right.category)
        .then_with(|| left.severity.cmp(&right.severity))
        .then_with(|| left.finding_type.cmp(&right.finding_type))
        .then_with(|| left.description.cmp(&right.description))
        .then_with(|| left.items.cmp(&right.items))
}

fn normalize_finding(raw: RawFinding, category: &str) -> Result<NativeKicadDrcFinding> {
    bounded_text(&raw.description, "finding description", MAX_TEXT_BYTES)?;
    bounded_text(&raw.finding_type, "finding type", MAX_TEXT_BYTES)?;
    if raw.excluded || !raw.comment.is_empty() {
        bail!("native KiCad PCB DRC excluded or commented findings are not accepted")
    }
    let severity = match raw.severity.as_str() {
        "error" | "warning" => raw.severity,
        _ => bail!("native KiCad PCB DRC contains unsupported finding severity"),
    };
    if raw.items.len() > MAX_ITEMS_PER_FINDING {
        bail!("native KiCad PCB DRC finding item count exceeds {MAX_ITEMS_PER_FINDING}")
    }
    let mut items = Vec::with_capacity(raw.items.len());
    for item in raw.items {
        bounded_text(&item.description, "item description", MAX_TEXT_BYTES)?;
        validate_uuid(&item.uuid)?;
        items.push(NativeKicadDrcItem {
            description: item.description,
            position_nm: position_nm(&item.pos)?,
        });
    }
    items.sort_by(item_cmp);
    Ok(NativeKicadDrcFinding {
        category: category.to_string(),
        description: raw.description,
        items,
        severity,
        finding_type: raw.finding_type,
    })
}

fn normalize_raw_report(
    raw: RawReport,
    source_bytes: &[u8],
    project: Option<NativeKicadDrcSourceIdentity>,
    rules_file: Option<NativeKicadDrcSourceIdentity>,
) -> Result<NativeKicadDrcReport> {
    if source_bytes.is_empty() || source_bytes.len() as u64 > MAX_INPUT_BYTES {
        bail!("native KiCad PCB DRC board source byte count is out of bounds")
    }
    if raw.schema != DRC_SCHEMA {
        bail!("native KiCad PCB DRC report schema is not drc.v1")
    }
    if raw.coordinate_units != "mm" {
        bail!("native KiCad PCB DRC report coordinate units are not mm")
    }
    bounded_text(&raw.date, "report date", MAX_TEXT_BYTES)?;
    if raw.included_severities != ["error", "warning"] {
        bail!("native KiCad PCB DRC report severities are not the fixed error/warning set")
    }
    // KiCad reports the staged basename.  Accepting an arbitrary source name
    // would allow an invocation to silently audit a different board.
    if raw.source != STAGED_INPUT_NAME {
        bail!("native KiCad PCB DRC report source is not the staged board basename")
    }
    bounded_version(&raw.kicad_version)?;
    if raw.ignored_checks.len() > MAX_IGNORED_CHECKS {
        bail!("native KiCad PCB DRC ignored-check count exceeds {MAX_IGNORED_CHECKS}")
    }
    let mut ignored_checks = Vec::with_capacity(raw.ignored_checks.len());
    let mut ignored_keys = BTreeSet::new();
    for check in raw.ignored_checks {
        bounded_text(
            &check.description,
            "ignored-check description",
            MAX_TEXT_BYTES,
        )?;
        bounded_text(&check.key, "ignored-check key", MAX_TEXT_BYTES)?;
        if !ignored_keys.insert(check.key.clone()) {
            bail!("native KiCad PCB DRC ignored-check keys are not unique")
        }
        ignored_checks.push(NativeKicadDrcIgnoredCheck {
            description: check.description,
            key: check.key,
        });
    }
    ignored_checks.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.description.cmp(&right.description))
    });

    let total_raw = raw
        .violations
        .len()
        .checked_add(raw.unconnected_items.len())
        .and_then(|count| count.checked_add(raw.schematic_parity.len()))
        .ok_or_else(|| anyhow::anyhow!("native KiCad PCB DRC finding count overflow"))?;
    if !raw.schematic_parity.is_empty() {
        bail!(
            "native KiCad PCB DRC schematic-parity findings are not accepted when the fixed invocation disables schematic parity"
        )
    }
    if total_raw > MAX_FINDINGS {
        bail!("native KiCad PCB DRC finding count exceeds {MAX_FINDINGS}")
    }
    let violation_count = raw.violations.len();
    let unconnected_item_count = raw.unconnected_items.len();
    let schematic_parity_count = raw.schematic_parity.len();
    let mut findings = Vec::with_capacity(total_raw);
    for finding in raw.violations {
        findings.push(normalize_finding(finding, "violation")?);
    }
    for finding in raw.unconnected_items {
        findings.push(normalize_finding(finding, "unconnected-item")?);
    }
    for finding in raw.schematic_parity {
        findings.push(normalize_finding(finding, "schematic-parity")?);
    }
    findings.sort_by(finding_cmp);
    let error_count = findings
        .iter()
        .filter(|finding| finding.severity == "error")
        .count();
    let warning_count = findings
        .iter()
        .filter(|finding| finding.severity == "warning")
        .count();
    let approved = error_count == 0 && warning_count == 0;
    let mut report = NativeKicadDrcReport {
        schema_version: 1,
        engine: "pcbex".to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        kicad_version: raw.kicad_version,
        source: source_identity(source_bytes),
        project,
        rules_file,
        invocation: NativeKicadDrcInvocation {
            command: "pcb drc".to_string(),
            format: "json".to_string(),
            units: "mm".to_string(),
            severities: vec!["error".to_string(), "warning".to_string()],
            exit_code_violations: true,
            all_track_errors: false,
            schematic_parity: false,
            refill_zones: false,
            save_board: false,
        },
        ignored_checks,
        findings,
        violation_count,
        unconnected_item_count,
        schematic_parity_count,
        error_count,
        warning_count,
        approved,
        run_sha256: String::new(),
    };
    report.run_sha256 = report_identity(&report)?;
    Ok(report)
}

fn parse_raw_report(
    bytes: &[u8],
    source_bytes: &[u8],
    project: Option<NativeKicadDrcSourceIdentity>,
    rules_file: Option<NativeKicadDrcSourceIdentity>,
) -> Result<NativeKicadDrcReport> {
    if bytes.is_empty() {
        bail!("native KiCad PCB DRC report is empty")
    }
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        bail!("native KiCad PCB DRC report exceeds {MAX_REPORT_BYTES} bytes")
    }
    reject_duplicate_json_keys(bytes).context("decoding native KiCad PCB DRC JSON report")?;
    let raw: RawReport =
        serde_json::from_slice(bytes).context("decoding native KiCad PCB DRC JSON report")?;
    normalize_raw_report(raw, source_bytes, project, rules_file)
}

/// Resolve explicit or same-stem project/rules companions.  A missing
/// automatically discovered companion is represented by `None`; an existing
/// symlink, directory, or other non-regular file is rejected by bounded I/O.
pub(crate) fn resolve_native_kicad_drc_companions(
    input: &Path,
    project: Option<&Path>,
    rules_file: Option<&Path>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    fn resolve_one(
        input: &Path,
        explicit: Option<&Path>,
        extension: &str,
    ) -> Result<Option<PathBuf>> {
        let candidate = explicit
            .map(Path::to_path_buf)
            .unwrap_or_else(|| input.with_extension(extension));
        if explicit.is_none() {
            match fs::symlink_metadata(&candidate) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "checking native KiCad PCB DRC companion {}",
                            candidate.display()
                        )
                    });
                }
            }
        }
        crate::bounded_io::read_with_limit(&candidate, MAX_INPUT_BYTES).with_context(|| {
            format!(
                "reading native KiCad PCB DRC companion {}",
                candidate.display()
            )
        })?;
        Ok(Some(candidate))
    }
    Ok((
        resolve_one(input, project, "kicad_pro")?,
        resolve_one(input, rules_file, "kicad_dru")?,
    ))
}

fn snapshot(path: &Path, label: &str) -> Result<(Vec<u8>, NativeKicadDrcSourceIdentity)> {
    let bytes = crate::bounded_io::read_with_limit(path, MAX_INPUT_BYTES).with_context(|| {
        format!(
            "reading bounded native KiCad PCB DRC {label} {}",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        bail!(
            "native KiCad PCB DRC {label} must not be empty: {}",
            path.display()
        )
    }
    let identity = source_identity(&bytes);
    Ok((bytes, identity))
}

fn stage_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    let mut file = File::create(path)
        .with_context(|| format!("creating staged native KiCad PCB DRC {label}"))?;
    file.write_all(bytes)
        .with_context(|| format!("staging native KiCad PCB DRC {label}"))?;
    file.sync_all()
        .with_context(|| format!("syncing staged native KiCad PCB DRC {label}"))?;
    Ok(())
}

fn resolve_kicad_cli(kicad_cli: &OsStr) -> Result<PathBuf> {
    let requested = Path::new(kicad_cli);
    if requested.as_os_str().is_empty() {
        bail!("native KiCad PCB DRC kicad-cli path must not be empty")
    }
    let mut components = requested.components();
    let first = components.next();
    let is_single_basename =
        matches!(first, Some(Component::Normal(_))) && components.next().is_none();
    // A single executable name deliberately remains a PATH lookup.  Once a
    // caller supplies a path component, make it absolute before changing the
    // child current directory to the private KiCad environment.
    if is_single_basename {
        return Ok(requested.to_path_buf());
    }
    if requested == Path::new(".") || requested == Path::new("..") {
        bail!("native KiCad PCB DRC kicad-cli path must not be . or ..")
    }
    let current_directory = std::env::current_dir()
        .context("resolving caller current directory for native KiCad PCB DRC kicad-cli")?;
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        current_directory.join(requested)
    };
    if absolute.as_os_str().is_empty() {
        bail!("native KiCad PCB DRC kicad-cli path resolved to empty")
    }
    Ok(absolute)
}

fn private_kicad_command(kicad_cli: &OsStr, environment: &Path) -> Result<std::process::Command> {
    let config = environment.join("config");
    let cache = environment.join("cache");
    let data = environment.join("data");
    for directory in [&config, &cache, &data] {
        fs::create_dir_all(directory)
            .with_context(|| format!("creating private KiCad directory {}", directory.display()))?;
    }
    let resolved_kicad_cli = resolve_kicad_cli(kicad_cli)?;
    let mut command = std::process::Command::new(resolved_kicad_cli);
    command
        .current_dir(environment)
        .env("HOME", environment)
        .env("USERPROFILE", environment)
        .env("KICAD_CONFIG_HOME", &config)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_DATA_HOME", &data)
        .env("APPDATA", &config)
        .env("LOCALAPPDATA", &cache)
        .args([
            "pcb",
            "drc",
            "--format",
            "json",
            "--units",
            "mm",
            "--severity-error",
            "--severity-warning",
            "--exit-code-violations",
            "--output",
        ])
        .arg(environment.join(STAGED_REPORT_NAME))
        .arg(environment.join(STAGED_INPUT_NAME));
    Ok(command)
}

/// Run native KiCad PCB DRC and return normalized evidence.
pub(crate) fn run_native_kicad_drc(
    input: &Path,
    project: Option<&Path>,
    rules_file: Option<&Path>,
    kicad_cli: &OsStr,
    cancellation: Option<&AtomicBool>,
) -> Result<NativeKicadDrcReport> {
    let (project_path, rules_path) =
        resolve_native_kicad_drc_companions(input, project, rules_file)?;
    let (source_bytes, source) = snapshot(input, "board")?;
    let (project_bytes, project_identity) = match project_path.as_deref() {
        Some(path) => {
            let (bytes, identity) = snapshot(path, "project")?;
            (Some(bytes), Some(identity))
        }
        None => (None, None),
    };
    let (rules_bytes, rules_identity) = match rules_path.as_deref() {
        Some(path) => {
            let (bytes, identity) = snapshot(path, "rules file")?;
            (Some(bytes), Some(identity))
        }
        None => (None, None),
    };

    let environment = tempfile::Builder::new()
        .prefix("pcbex-native-drc-")
        .tempdir()
        .context("creating private native KiCad PCB DRC environment")?;
    stage_file(
        &environment.path().join(STAGED_INPUT_NAME),
        &source_bytes,
        "board",
    )?;
    if let Some(bytes) = project_bytes.as_deref() {
        stage_file(
            &environment.path().join(STAGED_PROJECT_NAME),
            bytes,
            "project",
        )?;
    }
    if let Some(bytes) = rules_bytes.as_deref() {
        stage_file(
            &environment.path().join(STAGED_RULES_NAME),
            bytes,
            "rules file",
        )?;
    }

    let mut command = private_kicad_command(kicad_cli, environment.path())?;
    let limits = crate::bounded_process::ProcessLimits {
        timeout: KICAD_DRC_TIMEOUT,
        stdout_bytes: KICAD_DRC_STDOUT_BYTES,
        stderr_bytes: KICAD_DRC_STDERR_BYTES,
    };
    let output = crate::bounded_process::run_bounded(&mut command, limits, cancellation).map_err(
        |error| anyhow::anyhow!("bounded native KiCad PCB DRC execution failed: {error}"),
    )?;

    let staged_source = crate::bounded_io::read_with_limit(
        environment.path().join(STAGED_INPUT_NAME),
        MAX_INPUT_BYTES,
    )
    .context("re-reading staged native KiCad PCB DRC board")?;
    if staged_source != source_bytes {
        bail!("staged KiCad PCB board changed during native DRC")
    }
    if let Some(expected) = project_bytes.as_deref() {
        let staged = crate::bounded_io::read_with_limit(
            environment.path().join(STAGED_PROJECT_NAME),
            MAX_INPUT_BYTES,
        )
        .context("re-reading staged native KiCad PCB DRC project")?;
        if staged != expected {
            bail!("staged KiCad PCB project changed during native DRC")
        }
    }
    if let Some(expected) = rules_bytes.as_deref() {
        let staged = crate::bounded_io::read_with_limit(
            environment.path().join(STAGED_RULES_NAME),
            MAX_INPUT_BYTES,
        )
        .context("re-reading staged native KiCad PCB DRC rules file")?;
        if staged != expected {
            bail!("staged KiCad PCB rules file changed during native DRC")
        }
    }

    // Re-read every original input after the child exits.  This closes the
    // same-file mutation window and also rejects an auto-discovered companion
    // which appeared after staging.
    let (source_after_bytes, source_after) = snapshot(input, "board")?;
    if source_after_bytes != source_bytes || source_after != source {
        bail!("KiCad PCB board changed during native DRC")
    }
    let (project_after_path, rules_after_path) =
        resolve_native_kicad_drc_companions(input, project, rules_file)?;
    if project_after_path != project_path || rules_after_path != rules_path {
        bail!("native KiCad PCB DRC companion resolution changed during execution")
    }
    if let Some(path) = project_path.as_deref() {
        let (bytes, identity) = snapshot(path, "project")?;
        if Some(bytes) != project_bytes || Some(identity) != project_identity {
            bail!("KiCad PCB project changed during native DRC")
        }
    }
    if let Some(path) = rules_path.as_deref() {
        let (bytes, identity) = snapshot(path, "rules file")?;
        if Some(bytes) != rules_bytes || Some(identity) != rules_identity {
            bail!("KiCad PCB rules file changed during native DRC")
        }
    }

    let report_bytes = crate::bounded_io::read_with_limit(
        environment.path().join(STAGED_REPORT_NAME),
        MAX_REPORT_BYTES,
    )
    .context("reading bounded native KiCad PCB DRC report")?;
    let report = parse_raw_report(
        &report_bytes,
        &source_bytes,
        project_identity,
        rules_identity,
    )?;
    let code = output
        .status
        .code()
        .ok_or_else(|| anyhow::anyhow!("native KiCad PCB DRC terminated without an exit code"))?;
    let expected_nonzero = !report.findings.is_empty();
    match (code, expected_nonzero) {
        (0, false) | (5, true) => {}
        (0, true) => bail!("native KiCad PCB DRC returned success despite findings"),
        (5, false) => bail!("native KiCad PCB DRC returned violation status without findings"),
        (status, _) => {
            let diagnostic = first_diagnostic_line(&output.stderr)
                .or_else(|| first_diagnostic_line(&output.stdout))
                .unwrap_or_else(|| "no diagnostic output".to_string());
            bail!("native KiCad PCB DRC failed with status {status}: {diagnostic}")
        }
    }
    Ok(report)
}

fn first_diagnostic_line(bytes: &[u8]) -> Option<String> {
    let line = bytes
        .split(|byte| matches!(byte, b'\r' | b'\n'))
        .next()
        .unwrap_or_default();
    let line = &line[..line.len().min(MAX_TEXT_BYTES)];
    let rendered = String::from_utf8_lossy(line).trim().to_string();
    (!rendered.is_empty()).then_some(rendered)
}

fn validate_report(report: &NativeKicadDrcReport) -> Result<()> {
    if report.schema_version != 1 {
        bail!("unsupported native KiCad PCB DRC report schema version")
    }
    if report.engine != "pcbex" {
        bail!("native KiCad PCB DRC report engine must be pcbex")
    }
    bounded_version(&report.engine_version)?;
    bounded_version(&report.kicad_version)?;
    if report.source.bytes == 0 || report.source.bytes > MAX_INPUT_BYTES {
        bail!("native KiCad PCB DRC source byte count is out of bounds")
    }
    validate_sha256(&report.source.sha256, "source SHA-256")?;
    for (identity, label) in [
        (report.project.as_ref(), "project SHA-256"),
        (report.rules_file.as_ref(), "rules-file SHA-256"),
    ] {
        if let Some(identity) = identity {
            if identity.bytes == 0 || identity.bytes > MAX_INPUT_BYTES {
                bail!("native KiCad PCB DRC companion byte count is out of bounds")
            }
            validate_sha256(&identity.sha256, label)?;
        }
    }
    if report.invocation.command != "pcb drc"
        || report.invocation.format != "json"
        || report.invocation.units != "mm"
        || report.invocation.severities != ["error", "warning"]
        || !report.invocation.exit_code_violations
        || report.invocation.all_track_errors
        || report.invocation.schematic_parity
        || report.invocation.refill_zones
        || report.invocation.save_board
    {
        bail!("native KiCad PCB DRC report invocation is not fixed")
    }
    if report.ignored_checks.len() > MAX_IGNORED_CHECKS {
        bail!("native KiCad PCB DRC ignored-check count exceeds {MAX_IGNORED_CHECKS}")
    }
    let mut ignored_keys = BTreeSet::new();
    let mut expected_ignored = report.ignored_checks.clone();
    expected_ignored.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.description.cmp(&right.description))
    });
    if expected_ignored != report.ignored_checks {
        bail!("native KiCad PCB DRC ignored checks are not canonically sorted")
    }
    for check in &report.ignored_checks {
        bounded_text(
            &check.description,
            "ignored-check description",
            MAX_TEXT_BYTES,
        )?;
        bounded_text(&check.key, "ignored-check key", MAX_TEXT_BYTES)?;
        if !ignored_keys.insert(check.key.as_str()) {
            bail!("native KiCad PCB DRC ignored-check keys are not unique")
        }
    }
    if report.findings.len() > MAX_FINDINGS {
        bail!("native KiCad PCB DRC finding count exceeds {MAX_FINDINGS}")
    }
    let mut expected_findings = report.findings.clone();
    expected_findings.sort_by(finding_cmp);
    if expected_findings != report.findings {
        bail!("native KiCad PCB DRC findings are not canonically sorted")
    }
    let mut expected_violation = 0;
    let mut expected_unconnected = 0;
    let expected_parity = 0;
    let mut expected_error = 0;
    let mut expected_warning = 0;
    for finding in &report.findings {
        bounded_text(&finding.category, "finding category", MAX_TEXT_BYTES)?;
        bounded_text(&finding.description, "finding description", MAX_TEXT_BYTES)?;
        bounded_text(&finding.finding_type, "finding type", MAX_TEXT_BYTES)?;
        if finding.items.len() > MAX_ITEMS_PER_FINDING {
            bail!("native KiCad PCB DRC finding item count exceeds {MAX_ITEMS_PER_FINDING}")
        }
        let mut expected_items = finding.items.clone();
        expected_items.sort_by(item_cmp);
        if expected_items != finding.items {
            bail!("native KiCad PCB DRC finding items are not canonically sorted")
        }
        for item in &finding.items {
            bounded_text(&item.description, "item description", MAX_TEXT_BYTES)?;
            if item.position_nm.x < -1_000_000_000_000_000_i64
                || item.position_nm.x > 1_000_000_000_000_000_i64
                || item.position_nm.y < -1_000_000_000_000_000_i64
                || item.position_nm.y > 1_000_000_000_000_000_i64
            {
                bail!("native KiCad PCB DRC item position is out of bounds")
            }
        }
        match finding.category.as_str() {
            "violation" => expected_violation += 1,
            "unconnected-item" => expected_unconnected += 1,
            "schematic-parity" => {
                bail!(
                    "native KiCad PCB DRC schematic-parity findings are not accepted when the fixed invocation disables schematic parity"
                )
            }
            _ => bail!("native KiCad PCB DRC finding contains unsupported category"),
        }
        match finding.severity.as_str() {
            "error" => expected_error += 1,
            "warning" => expected_warning += 1,
            _ => bail!("native KiCad PCB DRC finding contains unsupported severity"),
        }
    }
    if report.violation_count != expected_violation
        || report.unconnected_item_count != expected_unconnected
        || report.schematic_parity_count != expected_parity
        || report.error_count != expected_error
        || report.warning_count != expected_warning
    {
        bail!("native KiCad PCB DRC report counts do not match findings")
    }
    if report.approved != (report.error_count == 0 && report.warning_count == 0) {
        bail!("native KiCad PCB DRC report approval does not match findings")
    }
    let expected = report_identity(report)?;
    if report.run_sha256 != expected {
        bail!("native KiCad PCB DRC report run SHA-256 does not match its contents")
    }
    Ok(())
}

/// Re-run native DRC and verify a retained normalized report byte-for-byte.
/// Rejected evidence is a valid result; callers decide whether approval is
/// required for their gate.
///
/// `decode_native_kicad_drc_report` is also used by CLI/MCP consumers which
/// receive a retained report as bytes and must not rely on a shallow JSON
/// value inspection.
#[allow(dead_code)]
pub(crate) fn verify_native_kicad_drc_report(
    input: &Path,
    retained_report_path: &Path,
    project: Option<&Path>,
    rules_file: Option<&Path>,
    kicad_cli: &OsStr,
    cancellation: Option<&AtomicBool>,
) -> Result<NativeKicadDrcReport> {
    let report_bytes_before =
        crate::bounded_io::read_with_limit(retained_report_path, MAX_REPORT_BYTES).with_context(
            || {
                format!(
                    "reading retained native KiCad PCB DRC report {}",
                    retained_report_path.display()
                )
            },
        )?;
    let retained = decode_native_kicad_drc_report(&report_bytes_before)?;
    let (resolved_project, resolved_rules) =
        resolve_native_kicad_drc_companions(input, project, rules_file)?;
    let (source_before, source_identity) = snapshot(input, "board")?;
    let project_identity = match resolved_project.as_deref() {
        Some(path) => Some(snapshot(path, "project")?.1),
        None => None,
    };
    let rules_identity = match resolved_rules.as_deref() {
        Some(path) => Some(snapshot(path, "rules file")?.1),
        None => None,
    };
    if retained.source != source_identity
        || retained.project != project_identity
        || retained.rules_file != rules_identity
    {
        bail!("retained native KiCad PCB DRC report input identities do not match sources")
    }

    let fresh = run_native_kicad_drc(input, project, rules_file, kicad_cli, cancellation)?;
    let source_after = crate::bounded_io::read_with_limit(input, MAX_INPUT_BYTES)
        .context("re-reading generated KiCad PCB board")?;
    if source_after != source_before {
        bail!("generated KiCad PCB board changed during native DRC verification")
    }
    let report_bytes_after =
        crate::bounded_io::read_with_limit(retained_report_path, MAX_REPORT_BYTES)
            .context("re-reading retained native KiCad PCB DRC report")?;
    if report_bytes_after != report_bytes_before {
        bail!("retained native KiCad PCB DRC report changed during verification")
    }
    let fresh_bytes = render_native_kicad_drc_report(&fresh)?;
    if fresh_bytes != report_bytes_after {
        bail!(
            "retained native KiCad PCB DRC report does not match a fresh native KiCad PCB DRC run"
        )
    }
    Ok(fresh)
}

/// Decode one retained normalized DRC report, rejecting duplicate keys,
/// unknown fields, invariant violations, and non-canonical JSON bytes.
pub(crate) fn decode_native_kicad_drc_report(bytes: &[u8]) -> Result<NativeKicadDrcReport> {
    if bytes.is_empty() {
        bail!("native KiCad PCB DRC report is empty")
    }
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        bail!("native KiCad PCB DRC report exceeds {MAX_REPORT_BYTES} bytes")
    }
    reject_duplicate_json_keys(bytes).context("decoding native KiCad PCB DRC report")?;
    let report: NativeKicadDrcReport =
        serde_json::from_slice(bytes).context("decoding native KiCad PCB DRC report")?;
    let canonical = render_native_kicad_drc_report(&report)?;
    if canonical != bytes {
        bail!("native KiCad PCB DRC report is not canonical normalized JSON")
    }
    Ok(report)
}

/// Render a report as compact canonical JSON with one trailing newline.
pub(crate) fn render_native_kicad_drc_report(report: &NativeKicadDrcReport) -> Result<Vec<u8>> {
    validate_report(report)?;
    let mut bytes =
        serde_json::to_vec(report).context("serializing native KiCad PCB DRC report")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        bail!("native KiCad PCB DRC report exceeds {MAX_REPORT_BYTES} bytes")
    }
    Ok(bytes)
}

/// Return the manually closed JSON schema for the native KiCad PCB DRC report.
pub(crate) fn native_kicad_drc_report_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/native-kicad-pcb-drc-v1.json",
        "title": "pcbex native KiCad PCB DRC evidence",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine", "engine_version", "kicad_version", "source",
            "project", "rules_file", "invocation", "ignored_checks", "findings",
            "violation_count", "unconnected_item_count", "schematic_parity_count",
            "error_count", "warning_count", "approved", "run_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "engine": {"const": "pcbex"},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": MAX_VERSION_BYTES},
            "kicad_version": {"type": "string", "minLength": 1, "maxLength": MAX_VERSION_BYTES},
            "source": {"$ref": "#/$defs/file_identity"},
            "project": {"anyOf": [{"$ref": "#/$defs/file_identity"}, {"type": "null"}]},
            "rules_file": {"anyOf": [{"$ref": "#/$defs/file_identity"}, {"type": "null"}]},
            "invocation": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "command", "format", "units", "severities", "exit_code_violations",
                    "all_track_errors", "schematic_parity", "refill_zones", "save_board"
                ],
                "properties": {
                    "command": {"const": "pcb drc"}, "format": {"const": "json"},
                    "units": {"const": "mm"}, "severities": {"const": ["error", "warning"]},
                    "exit_code_violations": {"const": true},
                    "all_track_errors": {"const": false},
                    "schematic_parity": {"const": false},
                    "refill_zones": {"const": false},
                    "save_board": {"const": false}
                }
            },
            "ignored_checks": {
                "type": "array", "maxItems": MAX_IGNORED_CHECKS,
                "items": {"$ref": "#/$defs/ignored_check"}
            },
            "findings": {
                "type": "array", "maxItems": MAX_FINDINGS,
                "items": {"$ref": "#/$defs/finding"}
            },
            "violation_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "unconnected_item_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "schematic_parity_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "error_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "warning_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "approved": {"type": "boolean"},
            "run_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        },
        "$defs": {
            "file_identity": {
                "type": "object", "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_INPUT_BYTES},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "ignored_check": {
                "type": "object", "additionalProperties": false,
                "required": ["description", "key"],
                "properties": {
                    "description": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "key": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES}
                }
            },
            "position": {
                "type": "object", "additionalProperties": false,
                "required": ["x", "y"],
                "properties": {
                    "x": {"type": "integer", "minimum": -1000000000000000_i64, "maximum": 1000000000000000_i64},
                    "y": {"type": "integer", "minimum": -1000000000000000_i64, "maximum": 1000000000000000_i64}
                }
            },
            "item": {
                "type": "object", "additionalProperties": false,
                "required": ["description", "position_nm"],
                "properties": {
                    "description": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "position_nm": {"$ref": "#/$defs/position"}
                }
            },
            "finding": {
                "type": "object", "additionalProperties": false,
                "required": ["category", "description", "items", "severity", "type"],
                "properties": {
                    "category": {"enum": ["violation", "unconnected-item", "schematic-parity"]},
                    "description": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "items": {"type": "array", "maxItems": MAX_ITEMS_PER_FINDING, "items": {"$ref": "#/$defs/item"}},
                    "severity": {"enum": ["error", "warning"]},
                    "type": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES}
                }
            }
        }
    })
}

fn reject_duplicate_json_keys(source: &[u8]) -> Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    deserializer
        .deserialize_any(DuplicateJsonValue)
        .map_err(|error| anyhow::anyhow!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| anyhow::anyhow!("invalid JSON: {error}"))
}

struct DuplicateJsonValue;

impl<'de> DeserializeSeed<'de> for DuplicateJsonValue {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateJsonValue {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_none<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }
    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence.next_element_seed(DuplicateJsonValue)?.is_some() {}
        Ok(())
    }
    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate JSON object key"));
            }
            map.next_value_seed(DuplicateJsonValue)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn raw_report(violations: Value, unconnected: Value, parity: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "$schema": DRC_SCHEMA,
            "coordinate_units": "mm",
            "date": "2026-08-05T00:00:00",
            "included_severities": ["error", "warning"],
            "kicad_version": "10.0.5-test",
            "schematic_parity": parity,
            "source": STAGED_INPUT_NAME,
            "unconnected_items": unconnected,
            "violations": violations,
        }))
        .unwrap()
    }

    fn item(description: &str, x: f64, y: f64, uuid: &str) -> Value {
        json!({
            "description": description,
            "pos": {"x": x, "y": y},
            "uuid": uuid,
        })
    }

    fn finding(description: &str, severity: &str, kind: &str, items: Value) -> Value {
        json!({
            "description": description,
            "items": items,
            "severity": severity,
            "type": kind,
        })
    }

    #[test]
    fn normalize_categories_counts_and_sorting() {
        let first = finding(
            "zeta",
            "warning",
            "z_type",
            json!([item(
                "item",
                1.2345678,
                -2.0,
                "00000000-0000-0000-0000-000000000001"
            )]),
        );
        let second = finding(
            "alpha",
            "error",
            "a_type",
            json!([item(
                "item",
                0.0000004,
                0.0000004,
                "11111111-1111-1111-1111-111111111111"
            )]),
        );
        let raw = raw_report(json!([first, second]), json!([]), json!([]));
        let report = parse_raw_report(&raw, b"board", None, None).unwrap();
        assert_eq!(report.violation_count, 2);
        assert_eq!(report.unconnected_item_count, 0);
        assert_eq!(report.schematic_parity_count, 0);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.warning_count, 1);
        assert!(!report.approved);
        assert_eq!(report.findings[0].description, "alpha");
        assert_eq!(report.findings[0].items[0].position_nm.x, 0);
        assert_eq!(report.findings[1].items[0].position_nm.x, 1_234_568);
    }

    #[test]
    fn raw_uuid_and_date_are_not_in_normalized_identity() {
        let make = |uuid: &str, date: &str| {
            let mut value: Value = serde_json::from_slice(&raw_report(
                json!([finding(
                    "one",
                    "error",
                    "clearance",
                    json!([item("pad", 1.0, 2.0, uuid)]),
                )]),
                json!([]),
                json!([]),
            ))
            .unwrap();
            value["date"] = json!(date);
            serde_json::to_vec(&value).unwrap()
        };
        let one = parse_raw_report(
            &make("00000000-0000-0000-0000-000000000001", "one"),
            b"board",
            None,
            None,
        )
        .unwrap();
        let two = parse_raw_report(
            &make("ffffffff-ffff-ffff-ffff-ffffffffffff", "two"),
            b"board",
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            render_native_kicad_drc_report(&one).unwrap(),
            render_native_kicad_drc_report(&two).unwrap()
        );
    }

    #[test]
    fn clean_report_is_approved_and_round_trips_canonically() {
        let report = parse_raw_report(
            &raw_report(json!([]), json!([]), json!([])),
            b"board",
            None,
            None,
        )
        .unwrap();
        assert!(report.approved);
        let rendered = render_native_kicad_drc_report(&report).unwrap();
        assert!(rendered.ends_with(b"\n"));
        assert_eq!(decode_native_kicad_drc_report(&rendered).unwrap(), report);
        assert_eq!(
            native_kicad_drc_report_schema()["additionalProperties"],
            false
        );
    }

    #[test]
    fn duplicate_unknown_and_nonfinite_or_excluded_findings_are_rejected() {
        let duplicate = br#"{"$schema":"https://schemas.kicad.org/drc.v1.json","$schema":"https://schemas.kicad.org/drc.v1.json"}"#;
        assert!(parse_raw_report(duplicate, b"board", None, None).is_err());
        let mut unknown: Value =
            serde_json::from_slice(&raw_report(json!([]), json!([]), json!([]))).unwrap();
        unknown["extra"] = json!(true);
        assert!(
            parse_raw_report(&serde_json::to_vec(&unknown).unwrap(), b"board", None, None).is_err()
        );
        let nonfinite = raw_report(
            json!([finding(
                "bad",
                "error",
                "x",
                json!([item(
                    "pad",
                    1.0e100,
                    0.0,
                    "00000000-0000-0000-0000-000000000001"
                )]),
            )]),
            json!([]),
            json!([]),
        );
        assert!(parse_raw_report(&nonfinite, b"board", None, None).is_err());
        let mut excluded: Value = serde_json::from_slice(&raw_report(
            json!([finding(
                "bad",
                "error",
                "x",
                json!([item(
                    "pad",
                    1.0,
                    0.0,
                    "00000000-0000-0000-0000-000000000001"
                )]),
            )]),
            json!([]),
            json!([]),
        ))
        .unwrap();
        excluded["violations"][0]["excluded"] = json!(true);
        assert!(
            parse_raw_report(
                &serde_json::to_vec(&excluded).unwrap(),
                b"board",
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn kicad9_missing_ignored_checks_is_accepted() {
        let mut raw: Value =
            serde_json::from_slice(&raw_report(json!([]), json!([]), json!([]))).unwrap();
        raw["kicad_version"] = json!("9.0.5-test");
        let report =
            parse_raw_report(&serde_json::to_vec(&raw).unwrap(), b"board", None, None).unwrap();
        assert_eq!(report.kicad_version, "9.0.5-test");
        assert!(report.ignored_checks.is_empty());
    }

    #[test]
    fn schematic_parity_is_rejected_when_fixed_invocation_disables_it() {
        let parity = json!([finding(
            "unexpected symbol",
            "error",
            "schematic_parity",
            json!([item(
                "pad",
                1.0,
                2.0,
                "00000000-0000-0000-0000-000000000001"
            )]),
        )]);
        assert!(
            parse_raw_report(
                &raw_report(json!([]), json!([]), parity),
                b"board",
                None,
                None
            )
            .is_err()
        );
    }

    #[test]
    fn companion_resolution_requires_regular_files_and_uses_same_stem() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("demo.kicad_pcb");
        let project = directory.path().join("demo.kicad_pro");
        let rules = directory.path().join("demo.kicad_dru");
        fs::write(&board, b"board").unwrap();
        fs::write(&project, b"{}").unwrap();
        fs::write(&rules, b"(version 1)").unwrap();
        let resolved = resolve_native_kicad_drc_companions(&board, None, None).unwrap();
        assert_eq!(resolved.0, Some(project));
        assert_eq!(resolved.1, Some(rules));
    }

    #[cfg(unix)]
    fn fake_cli(directory: &Path, status: i32, with_finding: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join(format!("fake-kicad-{status}-{}.sh", with_finding as u8));
        let uuid = "00000000-0000-0000-0000-000000000001";
        let violations = if with_finding {
            format!(
                "[{{\"description\":\"bad\",\"items\":[{{\"description\":\"pad\",\"pos\":{{\"x\":1.0,\"y\":2.0}},\"uuid\":\"{uuid}\"}}],\"severity\":\"error\",\"type\":\"clearance\"}}]"
            )
        } else {
            "[]".to_string()
        };
        let script = format!(
            "#!/bin/sh\nout=''\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then out=$2; shift 2; else shift; fi\ndone\nprintf '%s' '{{\"$schema\":\"{DRC_SCHEMA}\",\"coordinate_units\":\"mm\",\"date\":\"now\",\"included_severities\":[\"error\",\"warning\"],\"kicad_version\":\"10.0.5\",\"schematic_parity\":[],\"source\":\"input.kicad_pcb\",\"unconnected_items\":[],\"violations\":{violations}}}' > \"$out\"\nexit {status}\n"
        );
        fs::write(&path, script).unwrap();
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[cfg(unix)]
    #[test]
    fn runner_stages_companions_and_accepts_expected_status() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("demo.kicad_pcb");
        fs::write(&board, b"board").unwrap();
        fs::write(directory.path().join("demo.kicad_pro"), b"{}").unwrap();
        fs::write(directory.path().join("demo.kicad_dru"), b"(version 1)").unwrap();
        let cli = fake_cli(directory.path(), 0, false);
        let report = run_native_kicad_drc(&board, None, None, cli.as_os_str(), None).unwrap();
        assert!(report.approved);
        assert!(report.project.is_some());
        assert!(report.rules_file.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn runner_resolves_relative_cli_path_against_caller_directory() {
        let caller_directory = std::env::current_dir().unwrap();
        let directory = tempfile::tempdir_in(&caller_directory).unwrap();
        let board = directory.path().join("demo.kicad_pcb");
        fs::write(&board, b"board").unwrap();
        let cli = fake_cli(directory.path(), 0, false);
        let relative_cli = cli.strip_prefix(&caller_directory).unwrap();
        let report =
            run_native_kicad_drc(&board, None, None, relative_cli.as_os_str(), None).unwrap();
        assert!(report.approved);
    }

    #[cfg(unix)]
    #[test]
    fn runner_rejected_and_exit_contradiction_are_distinct() {
        let directory = tempfile::tempdir().unwrap();
        let board = directory.path().join("demo.kicad_pcb");
        fs::write(&board, b"board").unwrap();
        let rejected = fake_cli(directory.path(), 5, true);
        let report = run_native_kicad_drc(&board, None, None, rejected.as_os_str(), None).unwrap();
        assert!(!report.approved);
        assert_eq!(report.error_count, 1);
        let contradiction = fake_cli(directory.path(), 0, true);
        assert!(run_native_kicad_drc(&board, None, None, contradiction.as_os_str(), None).is_err());
    }
}
