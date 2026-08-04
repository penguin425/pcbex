//! Bounded, deterministic native KiCad schematic ERC evidence.
//!
//! KiCad writes ERC reports by pathname rather than to stdout.  This module
//! therefore keeps the caller's schematic and the KiCad report in one private
//! temporary directory, uses the shared process supervisor for the child, and
//! only returns a normalized report after both files have passed the bounded
//! regular-file boundary.

use anyhow::{Context, Result, bail};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

/// Maximum raw or rendered native ERC report size.
pub(crate) const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;

const MAX_SOURCE_BYTES: u64 = pcbex_kicad::CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_VERSION_BYTES: usize = 256;
const MAX_UUID_BYTES: usize = 128;
const MAX_SHEETS: usize = 1024;
const MAX_IGNORED_CHECKS: usize = 1024;
const MAX_FINDINGS: usize = 100_000;
const MAX_ITEMS_PER_FINDING: usize = 1024;
const MAX_COORDINATE_MM: f64 = 1_000_000_000.0;
const KICAD_ERC_TIMEOUT: Duration = Duration::from_secs(600);
const KICAD_ERC_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const KICAD_ERC_STDERR_BYTES: usize = 1024 * 1024;
const NATIVE_ERC_DOMAIN: &[u8] = b"pcbex/native-kicad-erc/v1\0";
const STAGED_INPUT_NAME: &str = "input.kicad_sch";
const STAGED_REPORT_NAME: &str = "erc.json";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcSourceIdentity {
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcInvocation {
    pub command: String,
    pub format: String,
    pub units: String,
    pub severity: String,
    pub exit_code_violations: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcIgnoredCheck {
    pub description: String,
    pub key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcPosition {
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcItem {
    pub description: String,
    pub pos: NativeKicadErcPosition,
    pub uuid: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcFinding {
    pub description: String,
    pub items: Vec<NativeKicadErcItem>,
    pub severity: String,
    pub sheet_path: String,
    pub sheet_uuid_path: String,
    #[serde(rename = "type")]
    pub finding_type: String,
}

/// Closed and deterministic native KiCad ERC evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcReport {
    pub schema_version: u32,
    pub engine: String,
    pub engine_version: String,
    pub kicad_version: String,
    pub source: NativeKicadErcSourceIdentity,
    pub invocation: NativeKicadErcInvocation,
    pub ignored_checks: Vec<NativeKicadErcIgnoredCheck>,
    pub findings: Vec<NativeKicadErcFinding>,
    pub error_count: usize,
    pub approved: bool,
    pub run_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReport {
    #[serde(rename = "$schema")]
    schema: String,
    coordinate_units: String,
    date: String,
    ignored_checks: Vec<RawIgnoredCheck>,
    included_severities: Vec<String>,
    kicad_version: String,
    sheets: Vec<RawSheet>,
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawIgnoredCheck {
    description: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSheet {
    path: String,
    uuid_path: String,
    violations: Vec<RawFinding>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFinding {
    description: String,
    items: Vec<RawItem>,
    severity: String,
    #[serde(rename = "type")]
    finding_type: String,
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
    source: &'a NativeKicadErcSourceIdentity,
    invocation: &'a NativeKicadErcInvocation,
    ignored_checks: &'a [NativeKicadErcIgnoredCheck],
    findings: &'a [NativeKicadErcFinding],
    error_count: usize,
    approved: bool,
}

fn report_identity(report: &NativeKicadErcReport) -> Result<String> {
    let identity = RunIdentity {
        schema_version: report.schema_version,
        engine: &report.engine,
        engine_version: &report.engine_version,
        kicad_version: &report.kicad_version,
        source: &report.source,
        invocation: &report.invocation,
        ignored_checks: &report.ignored_checks,
        findings: &report.findings,
        error_count: report.error_count,
        approved: report.approved,
    };
    let canonical =
        serde_json::to_vec(&identity).context("serializing native KiCad ERC run identity")?;
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_ERC_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn bounded_text(value: &str, label: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.bytes().any(|byte| byte == 0) {
        bail!("native KiCad ERC {label} must contain 1..={max_bytes} non-NUL bytes")
    }
    Ok(())
}

fn bounded_version(value: &str) -> Result<()> {
    bounded_text(value, "version", MAX_VERSION_BYTES)
}

fn validate_position(position: &RawPosition) -> Result<()> {
    if !position.x.is_finite()
        || !position.y.is_finite()
        || position.x.abs() > MAX_COORDINATE_MM
        || position.y.abs() > MAX_COORDINATE_MM
    {
        bail!("native KiCad ERC item position is not finite or bounded")
    }
    Ok(())
}

fn sort_ignored_checks(checks: &mut [NativeKicadErcIgnoredCheck]) {
    checks.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then_with(|| left.description.cmp(&right.description))
    });
}

fn item_cmp(left: &NativeKicadErcItem, right: &NativeKicadErcItem) -> Ordering {
    left.uuid
        .cmp(&right.uuid)
        .then_with(|| left.description.cmp(&right.description))
        .then_with(|| left.pos.x.total_cmp(&right.pos.x))
        .then_with(|| left.pos.y.total_cmp(&right.pos.y))
}

fn finding_cmp(left: &NativeKicadErcFinding, right: &NativeKicadErcFinding) -> Ordering {
    left.sheet_path
        .cmp(&right.sheet_path)
        .then_with(|| left.sheet_uuid_path.cmp(&right.sheet_uuid_path))
        .then_with(|| left.finding_type.cmp(&right.finding_type))
        .then_with(|| left.severity.cmp(&right.severity))
        .then_with(|| left.description.cmp(&right.description))
        .then_with(|| items_cmp(&left.items, &right.items))
}

fn items_cmp(left: &[NativeKicadErcItem], right: &[NativeKicadErcItem]) -> Ordering {
    for (left, right) in left.iter().zip(right) {
        let ordering = item_cmp(left, right);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.len().cmp(&right.len())
}

fn normalize_raw_report(raw: RawReport, source_bytes: &[u8]) -> Result<NativeKicadErcReport> {
    if raw.schema != "https://schemas.kicad.org/erc.v1.json" {
        bail!("unsupported native KiCad ERC report schema: {}", raw.schema)
    }
    if raw.coordinate_units != "mm" {
        bail!(
            "native KiCad ERC report uses unsupported coordinate units: {}",
            raw.coordinate_units
        )
    }
    bounded_text(&raw.date, "date", MAX_TEXT_BYTES)?;
    bounded_text(&raw.source, "source", MAX_TEXT_BYTES)?;
    if raw.source != STAGED_INPUT_NAME {
        bail!(
            "native KiCad ERC report source must be the fixed staged basename {STAGED_INPUT_NAME:?}"
        )
    }
    bounded_version(&raw.kicad_version)?;
    if raw.included_severities.len() != 1 || raw.included_severities[0] != "error" {
        bail!("native KiCad ERC report must include exactly the error severity")
    }
    if raw.sheets.is_empty() || raw.sheets.len() > MAX_SHEETS {
        bail!("native KiCad ERC report sheet count exceeds {MAX_SHEETS}")
    }
    if raw.ignored_checks.len() > MAX_IGNORED_CHECKS {
        bail!("native KiCad ERC ignored-check count exceeds {MAX_IGNORED_CHECKS}")
    }

    let mut ignored_checks = Vec::with_capacity(raw.ignored_checks.len());
    for check in raw.ignored_checks {
        bounded_text(
            &check.description,
            "ignored-check description",
            MAX_TEXT_BYTES,
        )?;
        bounded_text(&check.key, "ignored-check key", MAX_TEXT_BYTES)?;
        ignored_checks.push(NativeKicadErcIgnoredCheck {
            description: check.description,
            key: check.key,
        });
    }
    sort_ignored_checks(&mut ignored_checks);

    let mut findings = Vec::new();
    for sheet in raw.sheets {
        bounded_text(&sheet.path, "sheet path", MAX_TEXT_BYTES)?;
        bounded_text(&sheet.uuid_path, "sheet UUID path", MAX_UUID_BYTES)?;
        if sheet.violations.len() > MAX_FINDINGS.saturating_sub(findings.len()) {
            bail!("native KiCad ERC finding count exceeds {MAX_FINDINGS}")
        }
        for finding in sheet.violations {
            bounded_text(&finding.description, "finding description", MAX_TEXT_BYTES)?;
            bounded_text(&finding.finding_type, "finding type", MAX_TEXT_BYTES)?;
            if finding.severity != "error" {
                bail!(
                    "native KiCad ERC report contains an unsupported finding severity: {}",
                    finding.severity
                )
            }
            if finding.items.len() > MAX_ITEMS_PER_FINDING {
                bail!("native KiCad ERC finding item count exceeds {MAX_ITEMS_PER_FINDING}")
            }
            let mut items = Vec::with_capacity(finding.items.len());
            for item in finding.items {
                bounded_text(&item.description, "item description", MAX_TEXT_BYTES)?;
                bounded_text(&item.uuid, "item UUID", MAX_UUID_BYTES)?;
                validate_position(&item.pos)?;
                items.push(NativeKicadErcItem {
                    description: item.description,
                    pos: NativeKicadErcPosition {
                        x: item.pos.x,
                        y: item.pos.y,
                    },
                    uuid: item.uuid,
                });
            }
            items.sort_by(item_cmp);
            findings.push(NativeKicadErcFinding {
                description: finding.description,
                items,
                severity: finding.severity,
                sheet_path: sheet.path.clone(),
                sheet_uuid_path: sheet.uuid_path.clone(),
                finding_type: finding.finding_type,
            });
        }
    }
    findings.sort_by(finding_cmp);

    let source = NativeKicadErcSourceIdentity {
        bytes: source_bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(source_bytes)),
    };
    let mut report = NativeKicadErcReport {
        schema_version: 1,
        engine: "pcbex".to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        kicad_version: raw.kicad_version,
        source,
        invocation: NativeKicadErcInvocation {
            command: "sch erc".to_string(),
            format: "json".to_string(),
            units: "mm".to_string(),
            severity: "error".to_string(),
            exit_code_violations: true,
        },
        ignored_checks,
        findings,
        error_count: 0,
        approved: false,
        run_sha256: String::new(),
    };
    report.error_count = report.findings.len();
    report.approved = report.error_count == 0;
    report.run_sha256 = report_identity(&report)?;
    Ok(report)
}

fn parse_raw_report(bytes: &[u8], source_bytes: &[u8]) -> Result<NativeKicadErcReport> {
    if bytes.is_empty() {
        bail!("native KiCad ERC report is empty")
    }
    reject_duplicate_json_keys(bytes).context("decoding native KiCad ERC JSON report")?;
    let raw: RawReport =
        serde_json::from_slice(bytes).context("decoding native KiCad ERC JSON report")?;
    normalize_raw_report(raw, source_bytes)
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

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        Ok(())
    }

    fn visit_string<E>(self, _value: String) -> std::result::Result<Self::Value, E>
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

/// Run native KiCad ERC and return deterministic evidence.
pub(crate) fn run_native_kicad_erc(
    input: &Path,
    kicad_cli: &OsStr,
    cancellation: Option<&AtomicBool>,
) -> Result<NativeKicadErcReport> {
    let source_bytes = crate::bounded_io::read_with_limit(input, MAX_SOURCE_BYTES)
        .with_context(|| format!("reading bounded KiCad schematic {}", input.display()))?;
    if source_bytes.is_empty() {
        bail!("KiCad schematic must not be empty: {}", input.display())
    }
    std::str::from_utf8(&source_bytes)
        .with_context(|| format!("decoding KiCad schematic {} as UTF-8", input.display()))?;

    let environment = tempfile::Builder::new()
        .prefix("pcbex-native-erc-")
        .tempdir()
        .context("creating private native KiCad ERC environment")?;
    let staged_input = environment.path().join(STAGED_INPUT_NAME);
    let staged_report = environment.path().join(STAGED_REPORT_NAME);
    let mut staged_file = File::create(&staged_input)
        .with_context(|| format!("creating staged KiCad schematic {}", staged_input.display()))?;
    staged_file
        .write_all(&source_bytes)
        .with_context(|| format!("staging KiCad schematic {}", input.display()))?;
    staged_file
        .sync_all()
        .context("syncing staged KiCad schematic")?;

    let config = environment.path().join("config");
    let cache = environment.path().join("cache");
    let data = environment.path().join("data");
    for directory in [&config, &cache, &data] {
        fs::create_dir_all(directory)
            .with_context(|| format!("creating private KiCad directory {}", directory.display()))?;
    }

    let mut command = std::process::Command::new(kicad_cli);
    command
        .current_dir(environment.path())
        // Keep KiCad's supported profile/configuration locations private.
        // XDG variables cover native Unix paths; profile variables keep the
        // same boundary when this binary is run on Windows.
        .env("USERPROFILE", environment.path())
        .env("KICAD_CONFIG_HOME", &config)
        .env("XDG_CONFIG_HOME", &config)
        .env("XDG_CACHE_HOME", &cache)
        .env("XDG_DATA_HOME", &data)
        .env("APPDATA", &config)
        .env("LOCALAPPDATA", &cache)
        .args([
            "sch",
            "erc",
            "--format",
            "json",
            "--units",
            "mm",
            "--severity-error",
            "--exit-code-violations",
            "--output",
        ])
        .arg(&staged_report)
        .arg(&staged_input);
    let limits = crate::bounded_process::ProcessLimits {
        timeout: KICAD_ERC_TIMEOUT,
        stdout_bytes: KICAD_ERC_STDOUT_BYTES,
        stderr_bytes: KICAD_ERC_STDERR_BYTES,
    };
    let output = crate::bounded_process::run_bounded(&mut command, limits, cancellation)
        .map_err(|error| anyhow::anyhow!("bounded native KiCad ERC execution failed: {error}"))?;

    let staged_bytes = crate::bounded_io::read_with_limit(&staged_input, MAX_SOURCE_BYTES)
        .context("re-reading staged KiCad schematic")?;
    if staged_bytes != source_bytes {
        bail!("staged KiCad schematic changed during native ERC")
    }
    let report_bytes = crate::bounded_io::read_with_limit(&staged_report, MAX_REPORT_BYTES)
        .context("reading bounded native KiCad ERC report")?;
    let report = parse_raw_report(&report_bytes, &source_bytes)?;

    let code = output
        .status
        .code()
        .ok_or_else(|| anyhow::anyhow!("native KiCad ERC terminated without an exit code"))?;
    let expected_nonzero = report.error_count > 0;
    match (code, expected_nonzero) {
        (0, false) | (5, true) => {}
        (0, true) => bail!(
            "native KiCad ERC returned success despite {} error finding(s)",
            report.error_count
        ),
        (5, false) => bail!("native KiCad ERC returned violation status without errors"),
        (status, _) => {
            let diagnostic = first_diagnostic_line(&output.stderr)
                .or_else(|| first_diagnostic_line(&output.stdout))
                .unwrap_or_else(|| "no diagnostic output".to_string());
            bail!("native KiCad ERC failed with status {status}: {diagnostic}")
        }
    }
    Ok(report)
}

/// Re-run native ERC and verify a retained normalized report byte-for-byte.
///
/// The returned identity binds the exact retained report bytes; the separate
/// artifact identity is the schematic source identity embedded in that
/// report.  Callers can therefore compare the latter with their own generated
/// schematic binding before adding the native identity to a review request.
pub(crate) fn verify_native_kicad_erc_report(
    input: &Path,
    retained_report_path: &Path,
    kicad_cli: &OsStr,
    cancellation: Option<&AtomicBool>,
) -> Result<(
    pcbex_kicad::NativeKicadErcIdentity,
    pcbex_kicad::ExactArtifactIdentity,
)> {
    let source_before = crate::bounded_io::read_with_limit(input, MAX_SOURCE_BYTES)
        .with_context(|| format!("reading generated schematic {}", input.display()))?;
    if source_before.is_empty() {
        bail!("generated schematic must not be empty: {}", input.display());
    }

    let report_bytes_before =
        crate::bounded_io::read_with_limit(retained_report_path, MAX_REPORT_BYTES).with_context(
            || {
                format!(
                    "reading retained native KiCad ERC report {}",
                    retained_report_path.display()
                )
            },
        )?;
    let retained: NativeKicadErcReport = serde_json::from_slice(&report_bytes_before)
        .context("decoding retained native KiCad ERC report")?;
    let canonical_retained = render_native_kicad_erc_report(&retained)?;
    if canonical_retained != report_bytes_before {
        bail!(
            "retained native KiCad ERC report is not canonical normalized JSON: {}",
            retained_report_path.display()
        );
    }

    let fresh = run_native_kicad_erc(input, kicad_cli, cancellation)?;
    let source_after = crate::bounded_io::read_with_limit(input, MAX_SOURCE_BYTES)
        .with_context(|| format!("re-reading generated schematic {}", input.display()))?;
    if source_after != source_before {
        bail!("generated schematic changed during native KiCad ERC verification");
    }
    let report_bytes_after =
        crate::bounded_io::read_with_limit(retained_report_path, MAX_REPORT_BYTES).with_context(
            || {
                format!(
                    "re-reading retained native KiCad ERC report {}",
                    retained_report_path.display()
                )
            },
        )?;
    if report_bytes_after != report_bytes_before {
        bail!("retained native KiCad ERC report changed during verification");
    }
    let fresh_bytes = render_native_kicad_erc_report(&fresh)?;
    if fresh_bytes != report_bytes_after {
        bail!("retained native KiCad ERC report does not match a fresh native KiCad ERC run");
    }
    if !fresh.approved {
        bail!(
            "native KiCad ERC evidence is rejected with {} error finding(s)",
            fresh.error_count
        );
    }

    let source = pcbex_kicad::ExactArtifactIdentity {
        bytes: source_after.len() as u64,
        sha256: hex::encode(Sha256::digest(&source_after)),
    };
    if fresh.source.bytes != source.bytes || fresh.source.sha256 != source.sha256 {
        bail!("native KiCad ERC report schematic identity does not match the generated schematic");
    }
    let native_identity = pcbex_kicad::NativeKicadErcIdentity {
        schema_version: fresh.schema_version,
        report: pcbex_kicad::ExactArtifactIdentity {
            bytes: report_bytes_after.len() as u64,
            sha256: hex::encode(Sha256::digest(&report_bytes_after)),
        },
        run_sha256: fresh.run_sha256,
    };
    Ok((native_identity, source))
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

/// Render a report as compact canonical JSON with one trailing newline.
pub(crate) fn render_native_kicad_erc_report(report: &NativeKicadErcReport) -> Result<Vec<u8>> {
    if report.schema_version != 1 {
        bail!("unsupported native KiCad ERC report schema version")
    }
    if report.error_count != report.findings.len() {
        bail!("native KiCad ERC report error count does not match findings")
    }
    if report.approved != (report.error_count == 0) {
        bail!("native KiCad ERC report approval does not match error count")
    }
    let expected = report_identity(report)?;
    if report.run_sha256 != expected {
        bail!("native KiCad ERC report run SHA-256 does not match its contents")
    }
    let mut bytes = serde_json::to_vec(report).context("serializing native KiCad ERC report")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        bail!("native KiCad ERC report exceeds {MAX_REPORT_BYTES} bytes")
    }
    Ok(bytes)
}

/// Return the manually closed JSON schema for [`NativeKicadErcReport`].
pub(crate) fn native_kicad_erc_report_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/native-kicad-erc-v1.json",
        "title": "pcbex native KiCad schematic ERC evidence",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine", "engine_version", "kicad_version", "source",
            "invocation", "ignored_checks", "findings", "error_count", "approved", "run_sha256"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "engine": {"const": "pcbex"},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": MAX_VERSION_BYTES},
            "kicad_version": {"type": "string", "minLength": 1, "maxLength": MAX_VERSION_BYTES},
            "source": {
                "type": "object", "additionalProperties": false,
                "required": ["bytes", "sha256"],
                "properties": {
                    "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_SOURCE_BYTES},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            },
            "invocation": {
                "type": "object", "additionalProperties": false,
                "required": ["command", "format", "units", "severity", "exit_code_violations"],
                "properties": {
                    "command": {"const": "sch erc"},
                    "format": {"const": "json"},
                    "units": {"const": "mm"},
                    "severity": {"const": "error"},
                    "exit_code_violations": {"const": true}
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
            "error_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "approved": {"type": "boolean"},
            "run_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        },
        "$defs": {
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
                    "x": {"type": "number", "minimum": -MAX_COORDINATE_MM, "maximum": MAX_COORDINATE_MM},
                    "y": {"type": "number", "minimum": -MAX_COORDINATE_MM, "maximum": MAX_COORDINATE_MM}
                }
            },
            "item": {
                "type": "object", "additionalProperties": false,
                "required": ["description", "pos", "uuid"],
                "properties": {
                    "description": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "pos": {"$ref": "#/$defs/position"},
                    "uuid": {"type": "string", "minLength": 1, "maxLength": MAX_UUID_BYTES}
                }
            },
            "finding": {
                "type": "object", "additionalProperties": false,
                "required": ["description", "items", "severity", "sheet_path", "sheet_uuid_path", "type"],
                "properties": {
                    "description": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "items": {"type": "array", "maxItems": MAX_ITEMS_PER_FINDING, "items": {"$ref": "#/$defs/item"}},
                    "severity": {"const": "error"},
                    "sheet_path": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "sheet_uuid_path": {"type": "string", "minLength": 1, "maxLength": MAX_UUID_BYTES},
                    "type": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES}
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    fn raw_report(date: &str, finding: bool) -> String {
        let violations = if finding {
            json!([{
                "description": "Pin not connected",
                "items": [{
                    "description": "Symbol U1 Pin 1",
                    "pos": {"x": 1.0, "y": 2.0},
                    "uuid": "00000000-0000-0000-0000-000000000001"
                }],
                "severity": "error",
                "type": "pin_not_connected"
            }])
        } else {
            json!([])
        };
        serde_json::to_string(&json!({
            "$schema": "https://schemas.kicad.org/erc.v1.json",
            "coordinate_units": "mm",
            "date": date,
            "ignored_checks": [{"description": "ignored", "key": "ignored"}],
            "included_severities": ["error"],
            "kicad_version": "10.0.5",
            "sheets": [{"path": "/", "uuid_path": "/root", "violations": violations}],
            "source": "input.kicad_sch"
        }))
        .unwrap()
    }

    #[cfg(unix)]
    fn fake_cli(report: &str, status: i32) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("kicad-cli");
        let marker = directory.path().join("argv");
        let config_marker = directory.path().join("kicad-config-home");
        let script_source = format!(
            concat!(
                "#!/bin/sh\n",
                "printf '%s\\n' \"$@\" > '{}'\n",
                "printf '%s\\n' \"$KICAD_CONFIG_HOME\" > '{}'\n",
                "report=''\n",
                "while [ \"$#\" -gt 0 ]; do\n",
                "  if [ \"$1\" = '--output' ]; then report=\"$2\"; shift 2; else shift; fi\n",
                "done\n",
                "cat > \"$report\" <<'PCBEX_NATIVE_ERC_REPORT'\n{}\nPCBEX_NATIVE_ERC_REPORT\n",
                "exit {}\n",
            ),
            marker.display(),
            config_marker.display(),
            report,
            status
        );
        fs::write(&script, script_source).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        (directory, script)
    }

    #[cfg(unix)]
    #[test]
    fn strips_native_date_and_is_deterministic() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        let first_raw = raw_report("2026-01-01T00:00:00", false);
        let second_raw = raw_report("2027-02-02T00:00:00", false);
        let (first_directory, first_cli) = fake_cli(&first_raw, 0);
        let first = run_native_kicad_erc(&input, first_cli.as_os_str(), None).unwrap();
        let argv = fs::read_to_string(first_directory.path().join("argv")).unwrap();
        let argv = argv.lines().collect::<Vec<_>>();
        assert_eq!(argv.len(), 11);
        assert_eq!(
            &argv[..9],
            [
                "sch",
                "erc",
                "--format",
                "json",
                "--units",
                "mm",
                "--severity-error",
                "--exit-code-violations",
                "--output",
            ]
        );
        assert_eq!(
            std::path::Path::new(argv[9]).file_name(),
            Some(std::ffi::OsStr::new(STAGED_REPORT_NAME))
        );
        assert_eq!(
            std::path::Path::new(argv[10]).file_name(),
            Some(std::ffi::OsStr::new(STAGED_INPUT_NAME))
        );
        assert_eq!(
            std::path::Path::new(argv[9]).parent(),
            std::path::Path::new(argv[10]).parent()
        );
        let config_home =
            fs::read_to_string(first_directory.path().join("kicad-config-home")).unwrap();
        assert_eq!(
            std::path::Path::new(config_home.trim()),
            std::path::Path::new(argv[9])
                .parent()
                .unwrap()
                .join("config")
        );
        drop(first_directory);
        let (second_directory, second_cli) = fake_cli(&second_raw, 0);
        let second = run_native_kicad_erc(&input, second_cli.as_os_str(), None).unwrap();
        drop(second_directory);
        assert_eq!(
            render_native_kicad_erc_report(&first).unwrap(),
            render_native_kicad_erc_report(&second).unwrap()
        );
        assert!(first.approved);
        assert_eq!(first.error_count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn accepts_error_evidence_only_with_status_five() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        let (directory, cli) = fake_cli(&raw_report("2026-01-01T00:00:00", true), 5);
        let report = run_native_kicad_erc(&input, cli.as_os_str(), None).unwrap();
        drop(directory);
        assert!(!report.approved);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.findings[0].finding_type, "pin_not_connected");
    }

    #[cfg(unix)]
    #[test]
    fn verifies_retained_report_and_returns_source_identity() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        let retained = workspace.path().join("native-erc.json");
        let source = b"(kicad_sch (version 20231120))\n";
        fs::write(&input, source).unwrap();
        let (directory, cli) = fake_cli(&raw_report("2026-01-01T00:00:00", false), 0);
        let report = run_native_kicad_erc(&input, cli.as_os_str(), None).unwrap();
        drop(directory);
        let rendered = render_native_kicad_erc_report(&report).unwrap();
        fs::write(&retained, &rendered).unwrap();

        let (directory, cli) = fake_cli(&raw_report("2026-01-01T00:00:00", false), 0);
        let (identity, source_identity) =
            verify_native_kicad_erc_report(&input, &retained, cli.as_os_str(), None).unwrap();
        drop(directory);
        assert_eq!(identity.schema_version, 1);
        assert_eq!(identity.report.bytes, rendered.len() as u64);
        assert_eq!(
            identity.report.sha256,
            hex::encode(Sha256::digest(&rendered))
        );
        assert_eq!(identity.run_sha256, report.run_sha256);
        assert_eq!(source_identity.bytes, source.len() as u64);
        assert_eq!(source_identity.sha256, hex::encode(Sha256::digest(source)));
    }

    #[cfg(unix)]
    #[test]
    fn verifier_rejects_reproducible_error_evidence() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        let retained = workspace.path().join("native-erc.json");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        let raw = raw_report("2026-01-01T00:00:00", true);

        let (directory, cli) = fake_cli(&raw, 5);
        let report = run_native_kicad_erc(&input, cli.as_os_str(), None).unwrap();
        drop(directory);
        fs::write(&retained, render_native_kicad_erc_report(&report).unwrap()).unwrap();

        let (directory, cli) = fake_cli(&raw, 5);
        let error =
            verify_native_kicad_erc_report(&input, &retained, cli.as_os_str(), None).unwrap_err();
        drop(directory);
        assert!(error.to_string().contains("rejected with 1 error finding"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_status_mismatch_and_malformed_report() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        let (directory, cli) = fake_cli(&raw_report("2026-01-01T00:00:00", false), 5);
        let error = run_native_kicad_erc(&input, cli.as_os_str(), None).unwrap_err();
        drop(directory);
        assert!(error.to_string().contains("without errors"));

        let (directory, cli) = fake_cli("not-json", 0);
        let error = run_native_kicad_erc(&input, cli.as_os_str(), None).unwrap_err();
        drop(directory);
        assert!(
            error
                .to_string()
                .contains("decoding native KiCad ERC JSON report")
        );

        let duplicate = raw_report("2026-01-01T00:00:00", false).replace(
            "\"source\":\"input.kicad_sch\"",
            "\"source\":\"input.kicad_sch\",\"source\":\"input.kicad_sch\"",
        );
        let (directory, cli) = fake_cli(&duplicate, 0);
        let error = run_native_kicad_erc(&input, cli.as_os_str(), None).unwrap_err();
        drop(directory);
        assert!(format!("{error:#}").contains("duplicate JSON object key"));
    }

    #[test]
    fn schema_is_closed_and_contains_identity_fields() {
        let schema = native_kicad_erc_report_schema();
        assert_eq!(schema["additionalProperties"], false);
        assert!(
            schema["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "run_sha256")
        );
        assert!(schema["properties"]["source"]["properties"]["sha256"].is_object());
    }
}
