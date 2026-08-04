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
use std::collections::{BTreeMap, BTreeSet};
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
const MAX_WARNING_POLICY_BYTES: u64 = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_VERSION_BYTES: usize = 256;
const MAX_UUID_BYTES: usize = 128;
const MAX_SHEETS: usize = 1024;
const MAX_IGNORED_CHECKS: usize = 1024;
const MAX_FINDINGS: usize = 100_000;
const MAX_POLICY_FAILURES: usize = MAX_FINDINGS + MAX_IGNORED_CHECKS + 1;
const MAX_ITEMS_PER_FINDING: usize = 1024;
const MAX_COORDINATE_MM: f64 = 1_000_000_000.0;
const KICAD_ERC_TIMEOUT: Duration = Duration::from_secs(600);
const KICAD_ERC_STDOUT_BYTES: usize = 8 * 1024 * 1024;
const KICAD_ERC_STDERR_BYTES: usize = 1024 * 1024;
const NATIVE_ERC_DOMAIN: &[u8] = b"pcbex/native-kicad-erc/v1\0";
const NATIVE_ERC_WARNING_DOMAIN: &[u8] = b"pcbex/native-kicad-erc/v2\0";
const NATIVE_ERC_WARNING_POLICY_DOMAIN: &[u8] = b"pcbex/native-kicad-erc-warning-policy/v1\0";
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

/// One bounded warning budget entry.  A warning type is allowed only when it
/// appears in this list; an omitted type is rejected by the policy evaluator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcWarningLimit {
    pub finding_type: String,
    pub maximum_count: usize,
}

/// Closed, static native KiCad warning policy.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcWarningPolicy {
    pub schema_version: u32,
    pub id: String,
    pub maximum_total_warnings: usize,
    pub warning_limits: Vec<NativeKicadErcWarningLimit>,
    pub allowed_ignored_checks: Vec<String>,
}

/// Policy source and normalized policy identity retained in a v2 report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcWarningPolicyEvidence {
    pub source: NativeKicadErcSourceIdentity,
    pub policy_sha256: String,
    pub policy: NativeKicadErcWarningPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum NativeKicadErcPolicyFailureCode {
    Total,
    TypeNotAllowed,
    TypeLimit,
    IgnoredNotAllowed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcPolicyFailure {
    pub code: NativeKicadErcPolicyFailureCode,
    pub subject: String,
    pub actual_count: usize,
    pub maximum_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcWarningCount {
    pub finding_type: String,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcWarningInvocation {
    pub command: String,
    pub format: String,
    pub units: String,
    pub severities: Vec<String>,
    pub exit_code_violations: bool,
}

/// Closed native KiCad ERC evidence with a static warning budget.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeKicadErcWarningReport {
    pub schema_version: u32,
    pub engine: String,
    pub engine_version: String,
    pub kicad_version: String,
    pub source: NativeKicadErcSourceIdentity,
    pub invocation: NativeKicadErcWarningInvocation,
    pub ignored_checks: Vec<NativeKicadErcIgnoredCheck>,
    pub findings: Vec<NativeKicadErcFinding>,
    pub error_count: usize,
    pub warning_count: usize,
    pub warning_counts: Vec<NativeKicadErcWarningCount>,
    pub warning_policy: NativeKicadErcWarningPolicyEvidence,
    pub policy_failures: Vec<NativeKicadErcPolicyFailure>,
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

#[derive(Serialize)]
struct WarningRunIdentity<'a> {
    schema_version: u32,
    engine: &'a str,
    engine_version: &'a str,
    kicad_version: &'a str,
    source: &'a NativeKicadErcSourceIdentity,
    invocation: &'a NativeKicadErcWarningInvocation,
    ignored_checks: &'a [NativeKicadErcIgnoredCheck],
    findings: &'a [NativeKicadErcFinding],
    error_count: usize,
    warning_count: usize,
    warning_counts: &'a [NativeKicadErcWarningCount],
    warning_policy: &'a NativeKicadErcWarningPolicyEvidence,
    policy_failures: &'a [NativeKicadErcPolicyFailure],
    approved: bool,
}

fn warning_report_identity(report: &NativeKicadErcWarningReport) -> Result<String> {
    let identity = WarningRunIdentity {
        schema_version: report.schema_version,
        engine: &report.engine,
        engine_version: &report.engine_version,
        kicad_version: &report.kicad_version,
        source: &report.source,
        invocation: &report.invocation,
        ignored_checks: &report.ignored_checks,
        findings: &report.findings,
        error_count: report.error_count,
        warning_count: report.warning_count,
        warning_counts: &report.warning_counts,
        warning_policy: &report.warning_policy,
        policy_failures: &report.policy_failures,
        approved: report.approved,
    };
    let canonical = serde_json::to_vec(&identity)
        .context("serializing native KiCad ERC warning run identity")?;
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_ERC_WARNING_DOMAIN);
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}

fn warning_policy_sha256(policy: &NativeKicadErcWarningPolicy) -> Result<String> {
    let canonical =
        serde_json::to_vec(policy).context("serializing native KiCad ERC warning policy")?;
    if canonical.len() as u64 > MAX_WARNING_POLICY_BYTES {
        bail!("native KiCad ERC warning policy exceeds {MAX_WARNING_POLICY_BYTES} bytes")
    }
    let mut hasher = Sha256::new();
    hasher.update(NATIVE_ERC_WARNING_POLICY_DOMAIN);
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

fn validate_warning_policy(policy: &NativeKicadErcWarningPolicy) -> Result<()> {
    if policy.schema_version != 1 {
        bail!(
            "unsupported native KiCad ERC warning policy schema version {}",
            policy.schema_version
        )
    }
    bounded_text(&policy.id, "warning policy id", MAX_TEXT_BYTES)?;
    if policy.maximum_total_warnings > MAX_FINDINGS {
        bail!("native KiCad ERC warning policy total exceeds {MAX_FINDINGS}")
    }
    if policy.warning_limits.len() > MAX_FINDINGS {
        bail!("native KiCad ERC warning policy type count exceeds {MAX_FINDINGS}")
    }
    let mut previous_type: Option<&str> = None;
    for limit in &policy.warning_limits {
        bounded_text(
            &limit.finding_type,
            "warning policy finding type",
            MAX_TEXT_BYTES,
        )?;
        if limit.maximum_count > MAX_FINDINGS {
            bail!(
                "native KiCad ERC warning policy limit for {} exceeds {MAX_FINDINGS}",
                limit.finding_type
            )
        }
        if previous_type.is_some_and(|previous| previous >= limit.finding_type.as_str()) {
            bail!("native KiCad ERC warning policy warning_limits must be sorted and unique")
        }
        previous_type = Some(&limit.finding_type);
    }
    if policy.allowed_ignored_checks.len() > MAX_IGNORED_CHECKS {
        bail!("native KiCad ERC warning policy ignored-check count exceeds {MAX_IGNORED_CHECKS}")
    }
    let mut previous_key: Option<&str> = None;
    for key in &policy.allowed_ignored_checks {
        bounded_text(key, "warning policy ignored-check key", MAX_TEXT_BYTES)?;
        if previous_key.is_some_and(|previous| previous >= key.as_str()) {
            bail!(
                "native KiCad ERC warning policy allowed_ignored_checks must be sorted and unique"
            )
        }
        previous_key = Some(key);
    }
    Ok(())
}

fn parse_warning_policy(bytes: &[u8]) -> Result<NativeKicadErcWarningPolicy> {
    if bytes.is_empty() {
        bail!("native KiCad ERC warning policy is empty")
    }
    if bytes.len() as u64 > MAX_WARNING_POLICY_BYTES {
        bail!("native KiCad ERC warning policy exceeds {MAX_WARNING_POLICY_BYTES} bytes")
    }
    reject_duplicate_json_keys(bytes).context("decoding native KiCad ERC warning policy")?;
    let policy: NativeKicadErcWarningPolicy =
        serde_json::from_slice(bytes).context("decoding native KiCad ERC warning policy")?;
    validate_warning_policy(&policy)?;
    warning_policy_sha256(&policy)?;
    Ok(policy)
}

fn warning_policy_evidence(
    policy_bytes: &[u8],
    policy: NativeKicadErcWarningPolicy,
) -> Result<NativeKicadErcWarningPolicyEvidence> {
    let policy_sha256 = warning_policy_sha256(&policy)?;
    Ok(NativeKicadErcWarningPolicyEvidence {
        source: NativeKicadErcSourceIdentity {
            bytes: policy_bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(policy_bytes)),
        },
        policy_sha256,
        policy,
    })
}

fn evaluate_warning_policy(
    policy: &NativeKicadErcWarningPolicy,
    ignored_checks: &[NativeKicadErcIgnoredCheck],
    findings: &[NativeKicadErcFinding],
) -> Vec<NativeKicadErcPolicyFailure> {
    let limits = policy
        .warning_limits
        .iter()
        .map(|limit| (limit.finding_type.as_str(), limit.maximum_count))
        .collect::<BTreeMap<_, _>>();
    let mut warning_counts = BTreeMap::<&str, usize>::new();
    for finding in findings {
        if finding.severity == "warning" {
            *warning_counts
                .entry(finding.finding_type.as_str())
                .or_default() += 1;
        }
    }

    let warning_count = warning_counts.values().sum::<usize>();
    let mut failures = Vec::new();
    if warning_count > policy.maximum_total_warnings {
        failures.push(NativeKicadErcPolicyFailure {
            code: NativeKicadErcPolicyFailureCode::Total,
            subject: "total_warnings".to_string(),
            actual_count: warning_count,
            maximum_count: policy.maximum_total_warnings,
        });
    }
    for (finding_type, count) in warning_counts {
        let Some(maximum_count) = limits.get(finding_type) else {
            failures.push(NativeKicadErcPolicyFailure {
                code: NativeKicadErcPolicyFailureCode::TypeNotAllowed,
                subject: finding_type.to_string(),
                actual_count: count,
                maximum_count: 0,
            });
            continue;
        };
        if count > *maximum_count {
            failures.push(NativeKicadErcPolicyFailure {
                code: NativeKicadErcPolicyFailureCode::TypeLimit,
                subject: finding_type.to_string(),
                actual_count: count,
                maximum_count: *maximum_count,
            });
        }
    }
    let allowed_ignored_checks = policy
        .allowed_ignored_checks
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    for check in ignored_checks {
        if !allowed_ignored_checks.contains(check.key.as_str()) {
            failures.push(NativeKicadErcPolicyFailure {
                code: NativeKicadErcPolicyFailureCode::IgnoredNotAllowed,
                subject: check.key.clone(),
                actual_count: 1,
                maximum_count: 0,
            });
        }
    }
    failures.sort_by(|left, right| {
        failure_code_name(&left.code)
            .cmp(failure_code_name(&right.code))
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.actual_count.cmp(&right.actual_count))
            .then_with(|| left.maximum_count.cmp(&right.maximum_count))
    });
    failures
}

fn failure_code_name(code: &NativeKicadErcPolicyFailureCode) -> &str {
    match code {
        NativeKicadErcPolicyFailureCode::Total => "total",
        NativeKicadErcPolicyFailureCode::TypeNotAllowed => "type-not-allowed",
        NativeKicadErcPolicyFailureCode::TypeLimit => "type-limit",
        NativeKicadErcPolicyFailureCode::IgnoredNotAllowed => "ignored-not-allowed",
    }
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

fn normalize_raw_warning_report(
    raw: RawReport,
    source_bytes: &[u8],
    warning_policy: NativeKicadErcWarningPolicyEvidence,
) -> Result<NativeKicadErcWarningReport> {
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
    if raw.included_severities != ["error", "warning"] {
        bail!("native KiCad ERC warning report must include exactly error and warning severities")
    }
    if raw.sheets.is_empty() || raw.sheets.len() > MAX_SHEETS {
        bail!("native KiCad ERC report sheet count exceeds {MAX_SHEETS}")
    }
    if raw.ignored_checks.len() > MAX_IGNORED_CHECKS {
        bail!("native KiCad ERC ignored-check count exceeds {MAX_IGNORED_CHECKS}")
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
            bail!("native KiCad ERC report contains a duplicate ignored-check key")
        }
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
            if finding.severity != "error" && finding.severity != "warning" {
                bail!(
                    "native KiCad ERC warning report contains an unsupported finding severity: {}",
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

    let mut warning_counts = BTreeMap::<&str, usize>::new();
    let mut error_count = 0_usize;
    let mut warning_count = 0_usize;
    for finding in &findings {
        if finding.severity == "error" {
            error_count += 1;
        } else {
            warning_count += 1;
            *warning_counts
                .entry(finding.finding_type.as_str())
                .or_default() += 1;
        }
    }
    let warning_counts = warning_counts
        .into_iter()
        .map(|(finding_type, count)| NativeKicadErcWarningCount {
            finding_type: finding_type.to_string(),
            count,
        })
        .collect::<Vec<_>>();
    let policy_failures =
        evaluate_warning_policy(&warning_policy.policy, &ignored_checks, &findings);
    let source = NativeKicadErcSourceIdentity {
        bytes: source_bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(source_bytes)),
    };
    let mut report = NativeKicadErcWarningReport {
        schema_version: 2,
        engine: "pcbex".to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        kicad_version: raw.kicad_version,
        source,
        invocation: NativeKicadErcWarningInvocation {
            command: "sch erc".to_string(),
            format: "json".to_string(),
            units: "mm".to_string(),
            severities: vec!["error".to_string(), "warning".to_string()],
            exit_code_violations: true,
        },
        ignored_checks,
        findings,
        error_count,
        warning_count,
        warning_counts,
        warning_policy,
        policy_failures,
        approved: false,
        run_sha256: String::new(),
    };
    report.approved = report.error_count == 0 && report.policy_failures.is_empty();
    report.run_sha256 = warning_report_identity(&report)?;
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

fn parse_raw_warning_report(
    bytes: &[u8],
    source_bytes: &[u8],
    warning_policy: NativeKicadErcWarningPolicyEvidence,
) -> Result<NativeKicadErcWarningReport> {
    if bytes.is_empty() {
        bail!("native KiCad ERC report is empty")
    }
    reject_duplicate_json_keys(bytes).context("decoding native KiCad ERC JSON report")?;
    let raw: RawReport =
        serde_json::from_slice(bytes).context("decoding native KiCad ERC JSON report")?;
    normalize_raw_warning_report(raw, source_bytes, warning_policy)
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

/// Run native KiCad ERC with an explicit static warning budget.
///
/// The v1 runner above deliberately remains error-only.  This sibling invokes
/// KiCad with both error and warning severities, accepts KiCad status 5 when
/// any included finding exists (including policy-approved warnings), and
/// computes approval only from the normalized findings and policy failures.
pub(crate) fn run_native_kicad_erc_with_warning_policy(
    input: &Path,
    warning_policy_path: &Path,
    kicad_cli: &OsStr,
    cancellation: Option<&AtomicBool>,
) -> Result<NativeKicadErcWarningReport> {
    let policy_bytes =
        crate::bounded_io::read_with_limit(warning_policy_path, MAX_WARNING_POLICY_BYTES)
            .with_context(|| {
                format!(
                    "reading bounded native KiCad ERC warning policy {}",
                    warning_policy_path.display()
                )
            })?;
    let policy = parse_warning_policy(&policy_bytes)?;
    let warning_policy = warning_policy_evidence(&policy_bytes, policy)?;

    let source_bytes = crate::bounded_io::read_with_limit(input, MAX_SOURCE_BYTES)
        .with_context(|| format!("reading bounded KiCad schematic {}", input.display()))?;
    if source_bytes.is_empty() {
        bail!("KiCad schematic must not be empty: {}", input.display())
    }
    std::str::from_utf8(&source_bytes)
        .with_context(|| format!("decoding KiCad schematic {} as UTF-8", input.display()))?;

    let environment = tempfile::Builder::new()
        .prefix("pcbex-native-erc-warning-")
        .tempdir()
        .context("creating private native KiCad ERC warning environment")?;
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
            "--severity-warning",
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
    let output = crate::bounded_process::run_bounded(&mut command, limits, cancellation).map_err(
        |error| anyhow::anyhow!("bounded native KiCad ERC warning execution failed: {error}"),
    )?;

    let staged_bytes = crate::bounded_io::read_with_limit(&staged_input, MAX_SOURCE_BYTES)
        .context("re-reading staged KiCad schematic")?;
    if staged_bytes != source_bytes {
        bail!("staged KiCad schematic changed during native ERC warning run")
    }
    let policy_bytes_after =
        crate::bounded_io::read_with_limit(warning_policy_path, MAX_WARNING_POLICY_BYTES)
            .with_context(|| {
                format!(
                    "re-reading native KiCad ERC warning policy {}",
                    warning_policy_path.display()
                )
            })?;
    if policy_bytes_after != policy_bytes {
        bail!("native KiCad ERC warning policy changed during execution")
    }
    let report_bytes = crate::bounded_io::read_with_limit(&staged_report, MAX_REPORT_BYTES)
        .context("reading bounded native KiCad ERC warning report")?;
    let report = parse_raw_warning_report(&report_bytes, &source_bytes, warning_policy)?;

    let code = output.status.code().ok_or_else(|| {
        anyhow::anyhow!("native KiCad ERC warning terminated without an exit code")
    })?;
    let expected_nonzero = report.error_count + report.warning_count > 0;
    match (code, expected_nonzero) {
        (0, false) | (5, true) => {}
        (0, true) => bail!(
            "native KiCad ERC returned success despite {} finding(s)",
            report.error_count + report.warning_count
        ),
        (5, false) => bail!("native KiCad ERC returned violation status without findings"),
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

/// Re-run native ERC with a static warning policy and verify a retained v2
/// report byte-for-byte.  The policy source identity is part of the report,
/// so changing even formatting in the policy file invalidates the retained
/// evidence and forces a fresh report.
pub(crate) fn verify_native_kicad_erc_report_with_warning_policy(
    input: &Path,
    retained_report_path: &Path,
    warning_policy_path: &Path,
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
    let policy_bytes_before =
        crate::bounded_io::read_with_limit(warning_policy_path, MAX_WARNING_POLICY_BYTES)
            .with_context(|| {
                format!(
                    "reading retained native KiCad ERC warning policy {}",
                    warning_policy_path.display()
                )
            })?;
    let policy_before = parse_warning_policy(&policy_bytes_before)?;
    let policy_evidence_before = warning_policy_evidence(&policy_bytes_before, policy_before)?;

    let report_bytes_before =
        crate::bounded_io::read_with_limit(retained_report_path, MAX_REPORT_BYTES).with_context(
            || {
                format!(
                    "reading retained native KiCad ERC warning report {}",
                    retained_report_path.display()
                )
            },
        )?;
    let retained: NativeKicadErcWarningReport = serde_json::from_slice(&report_bytes_before)
        .context("decoding retained native KiCad ERC warning report")?;
    let canonical_retained = render_native_kicad_erc_warning_report(&retained)?;
    if canonical_retained != report_bytes_before {
        bail!(
            "retained native KiCad ERC warning report is not canonical normalized JSON: {}",
            retained_report_path.display()
        );
    }
    if retained.warning_policy != policy_evidence_before {
        bail!(
            "retained native KiCad ERC warning report does not match the supplied warning policy"
        );
    }

    let fresh = run_native_kicad_erc_with_warning_policy(
        input,
        warning_policy_path,
        kicad_cli,
        cancellation,
    )?;
    let source_after = crate::bounded_io::read_with_limit(input, MAX_SOURCE_BYTES)
        .with_context(|| format!("re-reading generated schematic {}", input.display()))?;
    if source_after != source_before {
        bail!("generated schematic changed during native KiCad ERC warning verification");
    }
    let report_bytes_after =
        crate::bounded_io::read_with_limit(retained_report_path, MAX_REPORT_BYTES).with_context(
            || {
                format!(
                    "re-reading retained native KiCad ERC warning report {}",
                    retained_report_path.display()
                )
            },
        )?;
    if report_bytes_after != report_bytes_before {
        bail!("retained native KiCad ERC warning report changed during verification");
    }
    let policy_bytes_after =
        crate::bounded_io::read_with_limit(warning_policy_path, MAX_WARNING_POLICY_BYTES)
            .with_context(|| {
                format!(
                    "re-reading native KiCad ERC warning policy {}",
                    warning_policy_path.display()
                )
            })?;
    if policy_bytes_after != policy_bytes_before {
        bail!("native KiCad ERC warning policy changed during verification");
    }
    let fresh_bytes = render_native_kicad_erc_warning_report(&fresh)?;
    if fresh_bytes != report_bytes_after {
        bail!(
            "retained native KiCad ERC warning report does not match a fresh native KiCad ERC run"
        );
    }
    if !fresh.approved {
        bail!(
            "native KiCad ERC warning evidence is rejected with {} error(s) and {} policy failure(s)",
            fresh.error_count,
            fresh.policy_failures.len()
        );
    }

    let source = pcbex_kicad::ExactArtifactIdentity {
        bytes: source_after.len() as u64,
        sha256: hex::encode(Sha256::digest(&source_after)),
    };
    if fresh.source.bytes != source.bytes || fresh.source.sha256 != source.sha256 {
        bail!(
            "native KiCad ERC warning report schematic identity does not match the generated schematic"
        );
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

fn validate_hex_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("native KiCad ERC {label} must be 64 lowercase hexadecimal characters")
    }
    Ok(())
}

fn validate_warning_report(report: &NativeKicadErcWarningReport) -> Result<()> {
    if report.schema_version != 2 {
        bail!("unsupported native KiCad ERC warning report schema version")
    }
    if report.engine != "pcbex" {
        bail!("native KiCad ERC warning report engine must be pcbex")
    }
    bounded_version(&report.engine_version)?;
    bounded_version(&report.kicad_version)?;
    if report.source.bytes == 0 || report.source.bytes > MAX_SOURCE_BYTES {
        bail!("native KiCad ERC warning report source byte count is out of bounds")
    }
    validate_hex_sha256(&report.source.sha256, "source SHA-256")?;
    if report.invocation.command != "sch erc"
        || report.invocation.format != "json"
        || report.invocation.units != "mm"
        || report.invocation.severities != ["error", "warning"]
        || !report.invocation.exit_code_violations
    {
        bail!("native KiCad ERC warning report invocation is not fixed")
    }
    if report.ignored_checks.len() > MAX_IGNORED_CHECKS {
        bail!("native KiCad ERC warning ignored-check count exceeds {MAX_IGNORED_CHECKS}")
    }
    let mut previous_ignored: Option<(&str, &str)> = None;
    let mut ignored_keys = BTreeSet::new();
    for check in &report.ignored_checks {
        bounded_text(
            &check.description,
            "ignored-check description",
            MAX_TEXT_BYTES,
        )?;
        bounded_text(&check.key, "ignored-check key", MAX_TEXT_BYTES)?;
        if !ignored_keys.insert(check.key.as_str()) {
            bail!("native KiCad ERC warning ignored-check keys are not unique")
        }
        if previous_ignored
            .is_some_and(|previous| (check.key.as_str(), check.description.as_str()) <= previous)
        {
            bail!("native KiCad ERC warning ignored checks are not sorted and unique")
        }
        previous_ignored = Some((&check.key, &check.description));
    }
    if report.findings.len() > MAX_FINDINGS {
        bail!("native KiCad ERC warning finding count exceeds {MAX_FINDINGS}")
    }
    let mut expected_findings = report.findings.clone();
    expected_findings.sort_by(finding_cmp);
    if expected_findings != report.findings {
        bail!("native KiCad ERC warning findings are not canonically sorted")
    }
    let mut expected_errors = 0_usize;
    let mut expected_warnings = 0_usize;
    let mut warning_counts_by_type = BTreeMap::<&str, usize>::new();
    for finding in &report.findings {
        bounded_text(&finding.description, "finding description", MAX_TEXT_BYTES)?;
        bounded_text(&finding.finding_type, "finding type", MAX_TEXT_BYTES)?;
        bounded_text(&finding.sheet_path, "sheet path", MAX_TEXT_BYTES)?;
        bounded_text(&finding.sheet_uuid_path, "sheet UUID path", MAX_UUID_BYTES)?;
        if finding.items.len() > MAX_ITEMS_PER_FINDING {
            bail!("native KiCad ERC warning finding item count exceeds {MAX_ITEMS_PER_FINDING}")
        }
        let mut expected_items = finding.items.clone();
        expected_items.sort_by(item_cmp);
        if expected_items != finding.items {
            bail!("native KiCad ERC warning finding items are not canonically sorted")
        }
        for item in &finding.items {
            bounded_text(&item.description, "item description", MAX_TEXT_BYTES)?;
            bounded_text(&item.uuid, "item UUID", MAX_UUID_BYTES)?;
            if !item.pos.x.is_finite()
                || !item.pos.y.is_finite()
                || item.pos.x.abs() > MAX_COORDINATE_MM
                || item.pos.y.abs() > MAX_COORDINATE_MM
            {
                bail!("native KiCad ERC warning item position is not finite or bounded")
            }
        }
        match finding.severity.as_str() {
            "error" => expected_errors += 1,
            "warning" => {
                expected_warnings += 1;
                *warning_counts_by_type
                    .entry(finding.finding_type.as_str())
                    .or_default() += 1;
            }
            _ => bail!("native KiCad ERC warning report contains unsupported severity"),
        }
    }
    if report.error_count != expected_errors || report.warning_count != expected_warnings {
        bail!("native KiCad ERC warning report counts do not match findings")
    }
    let expected_warning_counts = warning_counts_by_type
        .into_iter()
        .map(|(finding_type, count)| NativeKicadErcWarningCount {
            finding_type: finding_type.to_string(),
            count,
        })
        .collect::<Vec<_>>();
    if report.warning_counts != expected_warning_counts {
        bail!("native KiCad ERC warning report warning counts do not match findings")
    }

    if report.warning_policy.source.bytes == 0
        || report.warning_policy.source.bytes > MAX_WARNING_POLICY_BYTES
    {
        bail!("native KiCad ERC warning policy source byte count is out of bounds")
    }
    validate_hex_sha256(
        &report.warning_policy.source.sha256,
        "warning policy source SHA-256",
    )?;
    validate_warning_policy(&report.warning_policy.policy)?;
    let expected_policy_sha256 = warning_policy_sha256(&report.warning_policy.policy)?;
    if report.warning_policy.policy_sha256 != expected_policy_sha256 {
        bail!("native KiCad ERC warning policy SHA-256 does not match its contents")
    }
    let expected_failures = evaluate_warning_policy(
        &report.warning_policy.policy,
        &report.ignored_checks,
        &report.findings,
    );
    if report.policy_failures != expected_failures {
        bail!("native KiCad ERC warning policy failures do not match findings")
    }
    if report.policy_failures.len() > MAX_POLICY_FAILURES {
        bail!("native KiCad ERC warning policy failure count exceeds {MAX_POLICY_FAILURES}")
    }
    for failure in &report.policy_failures {
        bounded_text(
            &failure.subject,
            "warning policy failure subject",
            MAX_TEXT_BYTES,
        )?;
        if failure.actual_count == 0
            || failure.actual_count > MAX_FINDINGS
            || failure.maximum_count > MAX_FINDINGS
        {
            bail!("native KiCad ERC warning policy failure count is out of bounds")
        }
    }
    let expected_approved = report.error_count == 0 && report.policy_failures.is_empty();
    if report.approved != expected_approved {
        bail!("native KiCad ERC warning report approval does not match findings and policy")
    }
    let expected = warning_report_identity(report)?;
    if report.run_sha256 != expected {
        bail!("native KiCad ERC warning report run SHA-256 does not match its contents")
    }
    Ok(())
}

/// Render a v2 warning-policy report as compact canonical JSON with one final
/// newline.
pub(crate) fn render_native_kicad_erc_warning_report(
    report: &NativeKicadErcWarningReport,
) -> Result<Vec<u8>> {
    validate_warning_report(report)?;
    let mut bytes =
        serde_json::to_vec(report).context("serializing native KiCad ERC warning report")?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_REPORT_BYTES {
        bail!("native KiCad ERC warning report exceeds {MAX_REPORT_BYTES} bytes")
    }
    Ok(bytes)
}

/// Return the manually closed JSON schema for the warning policy document.
pub(crate) fn native_kicad_erc_warning_policy_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/native-kicad-erc-warning-policy-v1.json",
        "title": "pcbex native KiCad ERC warning policy",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "id", "maximum_total_warnings", "warning_limits",
            "allowed_ignored_checks"
        ],
        "properties": {
            "schema_version": {"const": 1},
            "id": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
            "maximum_total_warnings": {
                "type": "integer", "minimum": 0, "maximum": MAX_FINDINGS
            },
            "warning_limits": {
                "type": "array", "maxItems": MAX_FINDINGS,
                "items": {"$ref": "#/$defs/warning_limit"}
            },
            "allowed_ignored_checks": {
                "type": "array", "maxItems": MAX_IGNORED_CHECKS,
                "items": {
                    "type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES
                }
            }
        },
        "$defs": {
            "warning_limit": {
                "type": "object", "additionalProperties": false,
                "required": ["finding_type", "maximum_count"],
                "properties": {
                    "finding_type": {
                        "type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES
                    },
                    "maximum_count": {
                        "type": "integer", "minimum": 0, "maximum": MAX_FINDINGS
                    }
                }
            }
        }
    })
}

/// Return the manually closed JSON schema for the v2 warning-policy report.
pub(crate) fn native_kicad_erc_warning_report_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/native-kicad-erc-v2.json",
        "title": "pcbex native KiCad schematic ERC warning evidence",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "engine", "engine_version", "kicad_version", "source",
            "invocation", "ignored_checks", "findings", "error_count", "warning_count",
            "warning_counts", "warning_policy", "policy_failures", "approved", "run_sha256"
        ],
        "properties": {
            "schema_version": {"const": 2},
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
                "required": ["command", "format", "units", "severities", "exit_code_violations"],
                "properties": {
                    "command": {"const": "sch erc"},
                    "format": {"const": "json"},
                    "units": {"const": "mm"},
                    "severities": {"const": ["error", "warning"]},
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
            "warning_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS},
            "warning_counts": {
                "type": "array", "maxItems": MAX_FINDINGS,
                "items": {"$ref": "#/$defs/warning_count"}
            },
            "warning_policy": {"$ref": "#/$defs/policy_evidence"},
            "policy_failures": {
                "type": "array", "maxItems": MAX_POLICY_FAILURES,
                "items": {"$ref": "#/$defs/policy_failure"}
            },
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
                    "items": {
                        "type": "array", "maxItems": MAX_ITEMS_PER_FINDING,
                        "items": {"$ref": "#/$defs/item"}
                    },
                    "severity": {"enum": ["error", "warning"]},
                    "sheet_path": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "sheet_uuid_path": {"type": "string", "minLength": 1, "maxLength": MAX_UUID_BYTES},
                    "type": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES}
                }
            },
            "warning_count": {
                "type": "object", "additionalProperties": false,
                "required": ["finding_type", "count"],
                "properties": {
                    "finding_type": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "count": {"type": "integer", "minimum": 1, "maximum": MAX_FINDINGS}
                }
            },
            "policy": {
                "type": "object", "additionalProperties": false,
                "required": [
                    "schema_version", "id", "maximum_total_warnings", "warning_limits",
                    "allowed_ignored_checks"
                ],
                "properties": {
                    "schema_version": {"const": 1},
                    "id": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "maximum_total_warnings": {
                        "type": "integer", "minimum": 0, "maximum": MAX_FINDINGS
                    },
                    "warning_limits": {
                        "type": "array", "maxItems": MAX_FINDINGS,
                        "items": {"$ref": "#/$defs/warning_limit"}
                    },
                    "allowed_ignored_checks": {
                        "type": "array", "maxItems": MAX_IGNORED_CHECKS,
                        "items": {
                            "type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES
                        }
                    }
                }
            },
            "warning_limit": {
                "type": "object", "additionalProperties": false,
                "required": ["finding_type", "maximum_count"],
                "properties": {
                    "finding_type": {
                        "type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES
                    },
                    "maximum_count": {
                        "type": "integer", "minimum": 0, "maximum": MAX_FINDINGS
                    }
                }
            },
            "policy_evidence": {
                "type": "object", "additionalProperties": false,
                "required": ["source", "policy_sha256", "policy"],
                "properties": {
                    "source": {
                        "type": "object", "additionalProperties": false,
                        "required": ["bytes", "sha256"],
                        "properties": {
                            "bytes": {"type": "integer", "minimum": 1, "maximum": MAX_WARNING_POLICY_BYTES},
                            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                        }
                    },
                    "policy_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "policy": {"$ref": "#/$defs/policy"}
                }
            },
            "policy_failure": {
                "type": "object", "additionalProperties": false,
                "required": ["code", "subject", "actual_count", "maximum_count"],
                "properties": {
                    "code": {"enum": ["total", "type-not-allowed", "type-limit", "ignored-not-allowed"]},
                    "subject": {"type": "string", "minLength": 1, "maxLength": MAX_TEXT_BYTES},
                    "actual_count": {"type": "integer", "minimum": 1, "maximum": MAX_FINDINGS},
                    "maximum_count": {"type": "integer", "minimum": 0, "maximum": MAX_FINDINGS}
                }
            }
        }
    })
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
    fn raw_warning_report(date: &str, error: bool, warning: bool, ignored_key: &str) -> String {
        let mut violations = Vec::new();
        if error {
            violations.push(json!({
                "description": "Pin not connected",
                "items": [{
                    "description": "Symbol U1 Pin 1",
                    "pos": {"x": 1.0, "y": 2.0},
                    "uuid": "00000000-0000-0000-0000-000000000001"
                }],
                "severity": "error",
                "type": "pin_not_connected"
            }));
        }
        if warning {
            violations.push(json!({
                "description": "Warning",
                "items": [{
                    "description": "Symbol U1 Pin 2",
                    "pos": {"x": 3.0, "y": 4.0},
                    "uuid": "00000000-0000-0000-0000-000000000002"
                }],
                "severity": "warning",
                "type": "warning_type"
            }));
        }
        serde_json::to_string(&json!({
            "$schema": "https://schemas.kicad.org/erc.v1.json",
            "coordinate_units": "mm",
            "date": date,
            "ignored_checks": [{"description": "ignored", "key": ignored_key}],
            "included_severities": ["error", "warning"],
            "kicad_version": "10.0.5",
            "sheets": [{"path": "/", "uuid_path": "/root", "violations": violations}],
            "source": "input.kicad_sch"
        }))
        .unwrap()
    }

    #[cfg(unix)]
    fn warning_policy(maximum_total_warnings: usize, allowed: &[&str]) -> String {
        serde_json::to_string(&json!({
            "schema_version": 1,
            "id": "test-warning-policy",
            "maximum_total_warnings": maximum_total_warnings,
            "warning_limits": [{"finding_type": "warning_type", "maximum_count": 1}],
            "allowed_ignored_checks": allowed
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

    #[cfg(unix)]
    #[test]
    fn warning_runner_accepts_allowed_warning_with_status_five() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        let policy = workspace.path().join("warning-policy.json");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        fs::write(&policy, warning_policy(1, &["ignored"])).unwrap();
        let raw = raw_warning_report("2026-01-01T00:00:00", false, true, "ignored");
        let (directory, cli) = fake_cli(&raw, 5);
        let report =
            run_native_kicad_erc_with_warning_policy(&input, &policy, cli.as_os_str(), None)
                .unwrap();
        let argv = fs::read_to_string(directory.path().join("argv")).unwrap();
        let argv = argv.lines().collect::<Vec<_>>();
        assert_eq!(argv.len(), 12);
        assert_eq!(
            &argv[..10],
            [
                "sch",
                "erc",
                "--format",
                "json",
                "--units",
                "mm",
                "--severity-error",
                "--severity-warning",
                "--exit-code-violations",
                "--output",
            ]
        );
        assert_eq!(report.schema_version, 2);
        assert!(report.approved);
        assert_eq!(report.error_count, 0);
        assert_eq!(report.warning_count, 1);
        assert_eq!(report.warning_counts[0].finding_type, "warning_type");
        assert!(report.policy_failures.is_empty());
        assert_eq!(report.invocation.severities, ["error", "warning"]);
        let canonical_policy = serde_json::to_vec(&report.warning_policy.policy).unwrap();
        let mut policy_hasher = Sha256::new();
        policy_hasher.update(NATIVE_ERC_WARNING_POLICY_DOMAIN);
        policy_hasher.update(canonical_policy);
        assert_eq!(
            report.warning_policy.policy_sha256,
            hex::encode(policy_hasher.finalize())
        );
    }

    #[cfg(unix)]
    #[test]
    fn warning_policy_reports_total_type_and_ignored_failures() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        let policy = workspace.path().join("warning-policy.json");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        fs::write(
            &policy,
            serde_json::to_string(&json!({
                "schema_version": 1,
                "id": "test-warning-policy",
                "maximum_total_warnings": 0,
                "warning_limits": [],
                "allowed_ignored_checks": []
            }))
            .unwrap(),
        )
        .unwrap();
        let raw = raw_warning_report("2026-01-01T00:00:00", false, true, "ignored");
        let (directory, cli) = fake_cli(&raw, 5);
        let report =
            run_native_kicad_erc_with_warning_policy(&input, &policy, cli.as_os_str(), None)
                .unwrap();
        drop(directory);
        assert!(!report.approved);
        assert_eq!(
            report
                .policy_failures
                .iter()
                .map(|failure| failure.code.clone())
                .collect::<Vec<_>>(),
            vec![
                NativeKicadErcPolicyFailureCode::IgnoredNotAllowed,
                NativeKicadErcPolicyFailureCode::Total,
                NativeKicadErcPolicyFailureCode::TypeNotAllowed,
            ]
        );
        assert_eq!(report.policy_failures[0].subject, "ignored");
        assert_eq!(report.policy_failures[1].subject, "total_warnings");
        assert_eq!(report.policy_failures[2].subject, "warning_type");
        assert_eq!(report.policy_failures[2].maximum_count, 0);
        assert_eq!(
            report.warning_policy.source.bytes,
            fs::metadata(&policy).unwrap().len()
        );
        render_native_kicad_erc_warning_report(&report).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn warning_report_is_deterministic_and_verifies_fresh_replay() {
        let workspace = tempfile::tempdir().unwrap();
        let input = workspace.path().join("source.kicad_sch");
        let policy = workspace.path().join("warning-policy.json");
        let retained = workspace.path().join("warning-report.json");
        fs::write(&input, b"(kicad_sch (version 20231120))\n").unwrap();
        fs::write(&policy, warning_policy(1, &["ignored"])).unwrap();
        let first_raw = raw_warning_report("2026-01-01T00:00:00", false, true, "ignored");
        let (directory, cli) = fake_cli(&first_raw, 5);
        let first =
            run_native_kicad_erc_with_warning_policy(&input, &policy, cli.as_os_str(), None)
                .unwrap();
        drop(directory);
        let first_bytes = render_native_kicad_erc_warning_report(&first).unwrap();
        fs::write(&retained, &first_bytes).unwrap();

        let second_raw = raw_warning_report("2027-02-02T00:00:00", false, true, "ignored");
        let (directory, cli) = fake_cli(&second_raw, 5);
        let second =
            run_native_kicad_erc_with_warning_policy(&input, &policy, cli.as_os_str(), None)
                .unwrap();
        drop(directory);
        assert_eq!(
            first_bytes,
            render_native_kicad_erc_warning_report(&second).unwrap()
        );

        let (directory, cli) = fake_cli(&second_raw, 5);
        let (identity, source) = verify_native_kicad_erc_report_with_warning_policy(
            &input,
            &retained,
            &policy,
            cli.as_os_str(),
            None,
        )
        .unwrap();
        drop(directory);
        assert_eq!(identity.schema_version, 2);
        assert_eq!(identity.report.bytes, first_bytes.len() as u64);
        assert_eq!(identity.run_sha256, first.run_sha256);
        assert_eq!(source.bytes, fs::metadata(&input).unwrap().len());
    }

    #[test]
    fn warning_policy_and_report_schemas_are_closed() {
        let policy_schema = native_kicad_erc_warning_policy_schema();
        assert_eq!(policy_schema["additionalProperties"], false);
        assert_eq!(
            policy_schema["properties"]["schema_version"],
            json!({"const": 1})
        );
        let report_schema = native_kicad_erc_warning_report_schema();
        assert_eq!(report_schema["additionalProperties"], false);
        assert_eq!(
            report_schema["properties"]["schema_version"],
            json!({"const": 2})
        );
        assert_eq!(
            report_schema["$defs"]["policy_failure"]["properties"]["code"]["enum"],
            json!([
                "total",
                "type-not-allowed",
                "type-limit",
                "ignored-not-allowed"
            ])
        );
        assert_eq!(
            report_schema["$defs"]["policy_evidence"]["required"],
            json!(["source", "policy_sha256", "policy"])
        );
    }
}
