//! Bound, deterministic composition of the circuit-to-KiCad binding and the
//! existing hardware pipeline gate.
//!
//! This module deliberately does not invoke a command, a factory provider, or
//! a network service.  A plan is a closed JSON document containing the exact
//! byte/SHA-256 descriptor for every source accepted by [`PipelineInputs`].
//! Once the plan itself has been parsed, input and gate failures are retained
//! in a report; only failures in the runner's own staging/report machinery are
//! returned as `Err`.

use crate::bounded_io as fs;
use crate::firmware::{FIRMWARE_ARTIFACTS, MAX_FIRMWARE_ARTIFACT_BYTES};
use crate::manufacturing_limits::{
    MAX_PACKAGE_BYTES, portable_manufacturing_name_key, validate_manufacturing_basename,
};
use crate::physical_profile::MAX_PHYSICAL_PROFILE_BYTES;
use crate::pipeline::{PipelineGateReport, PipelineInputs, verify_pipeline};
use anyhow::{Context, Result, anyhow, bail};
use pcbex_kicad::{
    CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES, CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES,
    CircuitKicadBoardBindingReport, ElectricalPolicy,
    circuit_kicad_board_binding_report_json_schema, parse_electrical_policy,
    verify_circuit_kicad_board_binding,
};
use serde::{
    Deserialize, Serialize,
    de::{DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::path::{Component, Path, PathBuf};

const PLAN_SCHEMA_VERSION: u32 = 1;
const REPORT_SCHEMA_VERSION: u32 = 1;
const MAX_PLAN_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PLAN_PATH_CHARS: usize = 4096;
const MAX_INPUT_EVIDENCE: usize = 64;
const MAX_FAILURES: usize = 128;
const MAX_FAILURE_CHARS: usize = 4096;
// The CLI appends one newline before publishing through the shared 128 MiB
// output boundary, so reserve that final byte here.
const MAX_REPORT_BYTES: usize = 128 * 1024 * 1024 - 1;
const MAX_TOTAL_INPUT_BYTES: u64 = 512 * 1024 * 1024;
const PLAN_HASH_DOMAIN: &[u8] = b"pcbex:deterministic-pipeline-plan:v1\0";
const RUN_HASH_DOMAIN: &[u8] = b"pcbex:deterministic-pipeline-runner:v1\0";
const PORTABLE_PLAN_PATH_PATTERN: &str = r#"^(?!/)(?!.*//)(?!.*(?:^|/)\.{1,2}(?:/|$))(?!.*(?:^|/)(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\.|/|$))(?!.*[ .](?:/|$))(?:[^\\/:*?<>"|\u0000-\u001F\u007F]{1,255}/)*[^\\/:*?<>"|\u0000-\u001F\u007F]{1,255}$"#;

const MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_REVIEW_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ANALYSIS_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FACTORY_RECEIPT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FIRMWARE_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_CIRCUIT_SPEC_BYTES: u64 = pcbex_kicad::CIRCUIT_SPEC_V2_MAX_BYTES;

const ROLE_ORDER: [&str; 16] = [
    "circuit_spec",
    "schematic",
    "electrical_policy",
    "electrical_review",
    "board",
    "analysis_manifest",
    "analysis_checks",
    "quality",
    "analysis_project",
    "analysis_rules",
    "analysis_dfm_profile",
    "analysis_policy_pack",
    "analysis_physical_profile",
    "manufacturing_package",
    "firmware_manifest",
    "factory_receipt",
];

/// One explicit source descriptor in a deterministic runner plan.
///
/// `path` is resolved against the plan directory by
/// [`load_deterministic_pipeline_plan`].  The original relative spelling is
/// retained privately for stable report evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeterministicPipelineInputDescriptor {
    pub(crate) path: PathBuf,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    relative_path: String,
}

/// A parsed, closed deterministic pipeline plan (schema v1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeterministicPipelinePlan {
    pub(crate) schema_version: u32,
    pub(crate) circuit_spec: DeterministicPipelineInputDescriptor,
    pub(crate) schematic: DeterministicPipelineInputDescriptor,
    pub(crate) electrical_policy: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) electrical_review: DeterministicPipelineInputDescriptor,
    pub(crate) board: DeterministicPipelineInputDescriptor,
    pub(crate) analysis_manifest: DeterministicPipelineInputDescriptor,
    pub(crate) analysis_checks: DeterministicPipelineInputDescriptor,
    pub(crate) quality: DeterministicPipelineInputDescriptor,
    pub(crate) analysis_project: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) analysis_rules: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) analysis_dfm_profile: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) analysis_policy_pack: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) analysis_physical_profile: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) manufacturing_package: DeterministicPipelineInputDescriptor,
    pub(crate) firmware_manifest: DeterministicPipelineInputDescriptor,
    pub(crate) factory_receipt: Option<DeterministicPipelineInputDescriptor>,
    pub(crate) require_factory: bool,
    firmware_artifact_paths: [PathBuf; 7],
    plan_source_bytes: u64,
    plan_source_sha256: String,
    plan_sha256: String,
}

impl DeterministicPipelinePlan {
    /// Return every original source path, including the seven generated
    /// firmware siblings.  The order is fixed and does not depend on a
    /// directory enumeration.
    pub(crate) fn input_paths(&self) -> Vec<&Path> {
        let mut paths = Vec::with_capacity(23);
        for descriptor in [
            Some(&self.circuit_spec),
            Some(&self.schematic),
            self.electrical_policy.as_ref(),
            Some(&self.electrical_review),
            Some(&self.board),
            Some(&self.analysis_manifest),
            Some(&self.analysis_checks),
            Some(&self.quality),
            self.analysis_project.as_ref(),
            self.analysis_rules.as_ref(),
            self.analysis_dfm_profile.as_ref(),
            self.analysis_policy_pack.as_ref(),
            self.analysis_physical_profile.as_ref(),
            Some(&self.manufacturing_package),
            Some(&self.firmware_manifest),
            self.factory_receipt.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            paths.push(descriptor.path.as_path());
        }
        paths.extend(self.firmware_artifact_paths.iter().map(PathBuf::as_path));
        paths
    }

    fn descriptors(
        &self,
    ) -> impl Iterator<Item = (&'static str, &DeterministicPipelineInputDescriptor)> {
        [
            ("circuit_spec", &self.circuit_spec),
            ("schematic", &self.schematic),
            ("electrical_review", &self.electrical_review),
            ("board", &self.board),
            ("analysis_manifest", &self.analysis_manifest),
            ("analysis_checks", &self.analysis_checks),
            ("quality", &self.quality),
            ("manufacturing_package", &self.manufacturing_package),
            ("firmware_manifest", &self.firmware_manifest),
        ]
        .into_iter()
        .chain(
            self.electrical_policy
                .as_ref()
                .map(|value| ("electrical_policy", value)),
        )
        .chain(
            self.analysis_project
                .as_ref()
                .map(|value| ("analysis_project", value)),
        )
        .chain(
            self.analysis_rules
                .as_ref()
                .map(|value| ("analysis_rules", value)),
        )
        .chain(
            self.analysis_dfm_profile
                .as_ref()
                .map(|value| ("analysis_dfm_profile", value)),
        )
        .chain(
            self.analysis_policy_pack
                .as_ref()
                .map(|value| ("analysis_policy_pack", value)),
        )
        .chain(
            self.analysis_physical_profile
                .as_ref()
                .map(|value| ("analysis_physical_profile", value)),
        )
        .chain(
            self.factory_receipt
                .as_ref()
                .map(|value| ("factory_receipt", value)),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DeterministicPipelineInputEvidence {
    pub(crate) role: String,
    pub(crate) path: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
}

/// Closed aggregate report for one parsed deterministic runner plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct DeterministicPipelineReport {
    pub(crate) schema_version: u32,
    pub(crate) engine_version: String,
    pub(crate) plan_source_bytes: u64,
    pub(crate) plan_source_sha256: String,
    pub(crate) plan_sha256: String,
    pub(crate) input_evidence: Vec<DeterministicPipelineInputEvidence>,
    pub(crate) binding: Option<CircuitKicadBoardBindingReport>,
    pub(crate) pipeline: Option<PipelineGateReport>,
    pub(crate) failures: Vec<String>,
    pub(crate) approved: bool,
    pub(crate) run_sha256: String,
}

#[derive(Clone, Debug)]
struct Snapshot {
    bytes: Vec<u8>,
    evidence: DeterministicPipelineInputEvidence,
}

#[derive(Clone, Debug)]
struct FailureCollector {
    failures: Vec<String>,
}

impl FailureCollector {
    fn new() -> Self {
        Self {
            failures: Vec::new(),
        }
    }

    fn push(&mut self, message: impl Into<String>) {
        let message = message.into();
        self.failures.push(bound_text(&message, MAX_FAILURE_CHARS));
    }

    fn len(&self) -> usize {
        self.failures.len()
    }

    fn finish(mut self) -> Result<Vec<String>> {
        self.failures.sort();
        self.failures.dedup();
        if self.failures.len() > MAX_FAILURES {
            bail!("deterministic pipeline report exceeds its failure limit");
        }
        Ok(self.failures)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDescriptor {
    path: String,
    bytes: u64,
    sha256: String,
}

/// The wire type uses `Option<Option<T>>` for optional roles so a missing key
/// is distinguishable from the explicitly required JSON `null`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePlan {
    schema_version: u32,
    circuit_spec: WireDescriptor,
    schematic: WireDescriptor,
    electrical_policy: Option<Option<WireDescriptor>>,
    electrical_review: WireDescriptor,
    board: WireDescriptor,
    analysis_manifest: WireDescriptor,
    analysis_checks: WireDescriptor,
    quality: WireDescriptor,
    analysis_project: Option<Option<WireDescriptor>>,
    analysis_rules: Option<Option<WireDescriptor>>,
    analysis_dfm_profile: Option<Option<WireDescriptor>>,
    analysis_policy_pack: Option<Option<WireDescriptor>>,
    analysis_physical_profile: Option<Option<WireDescriptor>>,
    manufacturing_package: WireDescriptor,
    firmware_manifest: WireDescriptor,
    factory_receipt: Option<Option<WireDescriptor>>,
    require_factory: bool,
}

/// Parse a bounded plan and resolve every descriptor against its plan file's
/// directory.  Plan syntax/shape errors are ordinary `Err` results and no
/// report is produced.
pub(crate) fn load_deterministic_pipeline_plan(path: &Path) -> Result<DeterministicPipelinePlan> {
    reject_symlink_components(path, "plan").map_err(anyhow::Error::msg)?;
    let plan_path = fs::canonicalize(path)
        .with_context(|| format!("resolving deterministic pipeline plan {}", path.display()))?;
    let source = fs::read_with_limit(&plan_path, MAX_PLAN_BYTES)
        .with_context(|| format!("reading deterministic pipeline plan {}", path.display()))?;
    reject_duplicate_json_keys(&source)
        .with_context(|| format!("parsing deterministic pipeline plan {}", path.display()))?;
    let value: Value = serde_json::from_slice(&source)
        .with_context(|| format!("parsing deterministic pipeline plan {}", path.display()))?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("deterministic pipeline plan must be a JSON object"))?;
    for key in ROLE_ORDER.iter().chain(std::iter::once(&"require_factory")) {
        if !object.contains_key(*key) {
            bail!("deterministic pipeline plan is missing required key {key}");
        }
    }
    let wire: WirePlan = serde_json::from_value(value)
        .with_context(|| format!("parsing deterministic pipeline plan {}", path.display()))?;
    if wire.schema_version != PLAN_SCHEMA_VERSION {
        bail!(
            "unsupported deterministic pipeline plan schema version {}",
            wire.schema_version
        );
    }
    let plan_sha256 = domain_digest(PLAN_HASH_DOMAIN, &serde_json::to_vec(&wire)?);
    let plan_directory = plan_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("deterministic pipeline plan has no parent directory"))?;

    let circuit_spec = resolve_descriptor(
        &wire.circuit_spec,
        &plan_directory,
        "circuit_spec",
        MAX_CIRCUIT_SPEC_BYTES,
    )?;
    let schematic = resolve_descriptor(
        &wire.schematic,
        &plan_directory,
        "schematic",
        CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES,
    )?;
    let electrical_policy = resolve_optional_descriptor(
        wire.electrical_policy,
        &plan_directory,
        "electrical_policy",
        MAX_POLICY_BYTES,
    )?;
    let electrical_review = resolve_descriptor(
        &wire.electrical_review,
        &plan_directory,
        "electrical_review",
        MAX_REVIEW_BYTES,
    )?;
    let board = resolve_descriptor(
        &wire.board,
        &plan_directory,
        "board",
        CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES,
    )?;
    let analysis_manifest = resolve_descriptor(
        &wire.analysis_manifest,
        &plan_directory,
        "analysis_manifest",
        MAX_ANALYSIS_BYTES,
    )?;
    let analysis_checks = resolve_descriptor(
        &wire.analysis_checks,
        &plan_directory,
        "analysis_checks",
        MAX_ANALYSIS_BYTES,
    )?;
    let quality = resolve_descriptor(
        &wire.quality,
        &plan_directory,
        "quality",
        MAX_ANALYSIS_BYTES,
    )?;
    let analysis_project = resolve_optional_descriptor(
        wire.analysis_project,
        &plan_directory,
        "analysis_project",
        MAX_ANALYSIS_BYTES,
    )?;
    let analysis_rules = resolve_optional_descriptor(
        wire.analysis_rules,
        &plan_directory,
        "analysis_rules",
        MAX_ANALYSIS_BYTES,
    )?;
    let analysis_dfm_profile = resolve_optional_descriptor(
        wire.analysis_dfm_profile,
        &plan_directory,
        "analysis_dfm_profile",
        MAX_ANALYSIS_BYTES,
    )?;
    let analysis_policy_pack = resolve_optional_descriptor(
        wire.analysis_policy_pack,
        &plan_directory,
        "analysis_policy_pack",
        MAX_ANALYSIS_BYTES,
    )?;
    let analysis_physical_profile = resolve_optional_descriptor(
        wire.analysis_physical_profile,
        &plan_directory,
        "analysis_physical_profile",
        MAX_PHYSICAL_PROFILE_BYTES,
    )?;
    let manufacturing_package = resolve_descriptor(
        &wire.manufacturing_package,
        &plan_directory,
        "manufacturing_package",
        MAX_PACKAGE_BYTES,
    )?;
    let firmware_manifest = resolve_descriptor(
        &wire.firmware_manifest,
        &plan_directory,
        "firmware_manifest",
        MAX_FIRMWARE_MANIFEST_BYTES,
    )?;
    let factory_receipt = resolve_optional_descriptor(
        wire.factory_receipt,
        &plan_directory,
        "factory_receipt",
        MAX_FACTORY_RECEIPT_BYTES,
    )?;

    let mut seen_paths = std::collections::BTreeSet::new();
    let mut total_bytes = 0_u64;
    for (_, descriptor) in [
        ("circuit_spec", &circuit_spec),
        ("schematic", &schematic),
        ("electrical_review", &electrical_review),
        ("board", &board),
        ("analysis_manifest", &analysis_manifest),
        ("analysis_checks", &analysis_checks),
        ("quality", &quality),
        ("manufacturing_package", &manufacturing_package),
        ("firmware_manifest", &firmware_manifest),
    ]
    .into_iter()
    .chain(
        electrical_policy
            .as_ref()
            .map(|value| ("electrical_policy", value)),
    )
    .chain(
        analysis_project
            .as_ref()
            .map(|value| ("analysis_project", value)),
    )
    .chain(
        analysis_rules
            .as_ref()
            .map(|value| ("analysis_rules", value)),
    )
    .chain(
        analysis_dfm_profile
            .as_ref()
            .map(|value| ("analysis_dfm_profile", value)),
    )
    .chain(
        analysis_policy_pack
            .as_ref()
            .map(|value| ("analysis_policy_pack", value)),
    )
    .chain(
        analysis_physical_profile
            .as_ref()
            .map(|value| ("analysis_physical_profile", value)),
    )
    .chain(
        factory_receipt
            .as_ref()
            .map(|value| ("factory_receipt", value)),
    ) {
        if !seen_paths.insert(portable_manufacturing_name_key(&descriptor.relative_path)) {
            bail!("deterministic pipeline descriptors must not reuse the same path");
        }
        total_bytes = total_bytes
            .checked_add(descriptor.bytes)
            .ok_or_else(|| anyhow!("deterministic pipeline input byte count overflow"))?;
        if total_bytes > MAX_TOTAL_INPUT_BYTES {
            bail!("deterministic pipeline inputs exceed the aggregate byte limit");
        }
    }
    let firmware_artifact_paths = std::array::from_fn(|index| {
        firmware_manifest
            .path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(FIRMWARE_ARTIFACTS[index])
    });
    let firmware_relative_parent = Path::new(&firmware_manifest.relative_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    for name in FIRMWARE_ARTIFACTS {
        let relative = firmware_relative_parent
            .map(|parent| format!("{}/{name}", parent.to_string_lossy()))
            .unwrap_or_else(|| name.to_string());
        if !seen_paths.insert(portable_manufacturing_name_key(&relative)) {
            bail!(
                "deterministic pipeline descriptors must not reuse a derived firmware artifact path"
            );
        }
    }
    Ok(DeterministicPipelinePlan {
        schema_version: PLAN_SCHEMA_VERSION,
        circuit_spec,
        schematic,
        electrical_policy,
        electrical_review,
        board,
        analysis_manifest,
        analysis_checks,
        quality,
        analysis_project,
        analysis_rules,
        analysis_dfm_profile,
        analysis_policy_pack,
        analysis_physical_profile,
        manufacturing_package,
        firmware_manifest,
        factory_receipt,
        require_factory: wire.require_factory,
        firmware_artifact_paths,
        plan_source_bytes: source.len() as u64,
        plan_source_sha256: digest_hex(&source),
        plan_sha256,
    })
}

fn reject_duplicate_json_keys(source: &[u8]) -> Result<()> {
    let mut deserializer = serde_json::Deserializer::from_slice(source);
    deserializer
        .deserialize_any(DuplicateJsonValue)
        .map_err(|error| anyhow!("invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| anyhow!("invalid JSON: {error}"))
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

fn resolve_optional_descriptor(
    descriptor: Option<Option<WireDescriptor>>,
    plan_directory: &Path,
    role: &str,
    maximum: u64,
) -> Result<Option<DeterministicPipelineInputDescriptor>> {
    match descriptor {
        Some(Some(value)) => resolve_descriptor(&value, plan_directory, role, maximum).map(Some),
        Some(None) => Ok(None),
        None => Ok(None),
    }
}

fn resolve_descriptor(
    descriptor: &WireDescriptor,
    plan_directory: &Path,
    role: &str,
    maximum: u64,
) -> Result<DeterministicPipelineInputDescriptor> {
    validate_relative_path(&descriptor.path, role)?;
    if descriptor.bytes == 0 || descriptor.bytes > maximum {
        bail!("{role} descriptor byte count must be between 1 and {maximum}");
    }
    validate_sha256(&descriptor.sha256, role)?;
    let path = plan_directory.join(&descriptor.path);
    Ok(DeterministicPipelineInputDescriptor {
        path,
        bytes: descriptor.bytes,
        sha256: descriptor.sha256.clone(),
        relative_path: descriptor.path.clone(),
    })
}

fn validate_relative_path(value: &str, role: &str) -> Result<()> {
    if value.is_empty() || value.chars().count() > MAX_PLAN_PATH_CHARS {
        bail!("{role} descriptor path is empty or too long");
    }
    if value.contains('\\')
        || value.contains(':')
        || value.contains("//")
        || value.ends_with('/')
        || value.chars().any(char::is_control)
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        bail!("{role} descriptor path is not a portable relative file path");
    }
    for segment in value.split('/') {
        validate_manufacturing_basename(segment, 255, role)?;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        bail!("{role} descriptor path must be relative to the plan directory");
    }
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                bail!("{role} descriptor path must not contain a root or parent component")
            }
            Component::CurDir => {
                bail!("{role} descriptor path must not contain dot components")
            }
            Component::Normal(_) => {}
        }
    }
    if path.file_name().is_none() {
        bail!("{role} descriptor path must name a file");
    }
    Ok(())
}

fn validate_sha256(value: &str, role: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{role} descriptor SHA-256 must contain 64 lowercase hexadecimal digits");
    }
    Ok(())
}

/// Run the deterministic runner.  Input and gate failures are retained in the
/// returned report; private staging and report serialization failures remain
/// ordinary `Err` results.
pub(crate) fn run_deterministic_pipeline(
    plan: &DeterministicPipelinePlan,
) -> Result<DeterministicPipelineReport> {
    if plan.schema_version != PLAN_SCHEMA_VERSION {
        bail!(
            "unsupported deterministic pipeline plan schema version {}",
            plan.schema_version
        );
    }
    let stage = tempfile::Builder::new()
        .prefix("pcbex-deterministic-pipeline-")
        .tempdir()
        .context("creating private deterministic pipeline staging directory")?;
    let mut failures = FailureCollector::new();
    let mut evidence = Vec::new();

    let mut targets = BTreeMap::<&'static str, PathBuf>::new();
    for (role, descriptor) in plan.descriptors() {
        let target = stage_target(stage.path(), role, &descriptor.path)?;
        targets.insert(role, target);
    }

    // The firmware directory is inspected before any source is staged.  This
    // closes the otherwise ambiguous boundary where an artifact could be
    // added after the manifest was read.
    let firmware_failure_start = failures.len();
    let firmware_bundle = prescan_firmware_bundle(plan, &mut failures);
    let mut firmware_inputs_ready = firmware_bundle
        .as_ref()
        .is_some_and(|bundle| bundle.len() == FIRMWARE_ARTIFACTS.len() + 1)
        && failures.len() == firmware_failure_start;

    let mut snapshots = BTreeMap::<&'static str, Snapshot>::new();
    for (role, descriptor) in plan.descriptors() {
        match read_expected(role, descriptor) {
            Ok(snapshot) => {
                if let Some(target) = targets.get(role) {
                    fs::write(target, &snapshot.bytes)
                        .with_context(|| format!("staging deterministic pipeline input {role}"))?;
                }
                evidence.push(snapshot.evidence.clone());
                snapshots.insert(role, snapshot);
            }
            Err(error) => failures.push(error),
        }
    }

    // Stage all seven firmware sources into the same role directory as
    // manifest.json; verify_pipeline intentionally validates the exact sibling
    // set relative to that manifest path.
    if let Some(bundle) = firmware_bundle.as_ref() {
        let manifest_target = targets
            .get("firmware_manifest")
            .ok_or_else(|| anyhow!("firmware manifest staging target is missing"))?;
        let parent = manifest_target
            .parent()
            .ok_or_else(|| anyhow!("firmware manifest staging target has no parent"))?;
        for name in FIRMWARE_ARTIFACTS {
            let Some(snapshot) = bundle.get(name) else {
                continue;
            };
            let target = parent.join(name);
            fs::write(&target, &snapshot.bytes)
                .with_context(|| format!("staging firmware artifact {name}"))?;
            evidence.push(snapshot.evidence.clone());
        }
    }

    match (
        firmware_bundle
            .as_ref()
            .and_then(|bundle| bundle.get("manifest.json")),
        snapshots.get("firmware_manifest"),
    ) {
        (Some(prescanned), Some(explicit)) if prescanned.bytes == explicit.bytes => {}
        _ => {
            firmware_inputs_ready = false;
            failures
                .push("firmware_manifest: manifest snapshot does not match the prescanned bundle");
        }
    }

    // The manifest is also an explicit descriptor and is read again above.
    // Re-scan after every snapshot so an entry added or removed between that
    // read and the firmware pre-scan cannot be hidden by the private stage.
    if firmware_bundle.is_some() {
        let parent = plan
            .firmware_manifest
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut expected = FIRMWARE_ARTIFACTS
            .iter()
            .map(ToString::to_string)
            .chain(std::iter::once("manifest.json".to_string()))
            .collect::<Vec<_>>();
        expected.sort();
        match scan_firmware_entries(parent) {
            Ok(actual) if actual == expected => {}
            Ok(_) => {
                firmware_inputs_ready = false;
                failures.push("firmware_manifest: firmware bundle changed after snapshot");
            }
            Err(error) => {
                firmware_inputs_ready = false;
                failures.push(format!("firmware_manifest: {error}"));
            }
        }
    }

    evidence.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.path.cmp(&right.path))
    });
    evidence.dedup_by(|left, right| left.role == right.role && left.path == right.path);
    if evidence.len() > MAX_INPUT_EVIDENCE {
        bail!("deterministic pipeline report exceeds its input evidence limit");
    }
    let aggregate_bytes = evidence
        .iter()
        .try_fold(0_u64, |total, item| total.checked_add(item.bytes));
    let aggregate_within_limit =
        aggregate_bytes.is_some_and(|bytes| bytes <= MAX_TOTAL_INPUT_BYTES);
    if !aggregate_within_limit {
        failures.push("inputs: aggregate staged input bytes exceed the runner limit");
    }

    // Each gate can retain evidence independently when all of its own exact
    // inputs were staged. Shared inputs (schematic, board, and an explicit
    // policy) remain authoritative for both gates. The aggregate byte bound is
    // global and suppresses further parsing for either gate.
    let binding_snapshots_ready = aggregate_within_limit
        && snapshots.contains_key("circuit_spec")
        && snapshots.contains_key("schematic")
        && snapshots.contains_key("board")
        && plan
            .electrical_policy
            .as_ref()
            .is_none_or(|_| snapshots.contains_key("electrical_policy"));

    let binding_policy = if binding_snapshots_ready {
        match plan.electrical_policy.as_ref() {
            None => Some(ElectricalPolicy::default()),
            Some(_) => match snapshots.get("electrical_policy") {
                Some(snapshot) => match std::str::from_utf8(&snapshot.bytes) {
                    Ok(source) => match parse_electrical_policy(source) {
                        Ok(policy) => Some(policy),
                        Err(error) => {
                            failures
                                .push(format!("electrical_policy: cannot parse policy: {error}"));
                            None
                        }
                    },
                    Err(error) => {
                        failures.push(format!("electrical_policy: input is not UTF-8: {error}"));
                        None
                    }
                },
                None => None,
            },
        }
    } else {
        None
    };

    let binding = if binding_snapshots_ready && binding_policy.is_some() {
        let circuit = snapshots
            .get("circuit_spec")
            .and_then(|snapshot| std::str::from_utf8(&snapshot.bytes).ok());
        let schematic = snapshots
            .get("schematic")
            .and_then(|snapshot| std::str::from_utf8(&snapshot.bytes).ok());
        let board = snapshots
            .get("board")
            .and_then(|snapshot| std::str::from_utf8(&snapshot.bytes).ok());
        match (circuit, schematic, board, binding_policy.as_ref()) {
            (Some(circuit), Some(schematic), Some(board), Some(policy)) => {
                match verify_circuit_kicad_board_binding(circuit, schematic, board, policy) {
                    Ok(report) => Some(report),
                    Err(error) => {
                        failures.push(format!("binding: {error}"));
                        None
                    }
                }
            }
            _ => {
                failures
                    .push("binding: circuit_spec, schematic, and board must be UTF-8".to_string());
                None
            }
        }
    } else {
        None
    };

    let pipeline_targets = |role: &'static str| {
        targets
            .get(role)
            .map(PathBuf::as_path)
            .expect("required staging target was created above")
    };
    let pipeline_inputs_ready = aggregate_within_limit
        && [
            "schematic",
            "electrical_review",
            "board",
            "analysis_manifest",
            "analysis_checks",
            "quality",
            "manufacturing_package",
            "firmware_manifest",
        ]
        .into_iter()
        .all(|role| snapshots.contains_key(role))
        && [
            ("electrical_policy", plan.electrical_policy.is_some()),
            ("analysis_project", plan.analysis_project.is_some()),
            ("analysis_rules", plan.analysis_rules.is_some()),
            ("analysis_dfm_profile", plan.analysis_dfm_profile.is_some()),
            ("analysis_policy_pack", plan.analysis_policy_pack.is_some()),
            (
                "analysis_physical_profile",
                plan.analysis_physical_profile.is_some(),
            ),
            ("factory_receipt", plan.factory_receipt.is_some()),
        ]
        .into_iter()
        .all(|(role, configured)| !configured || snapshots.contains_key(role))
        && firmware_inputs_ready;
    let pipeline = if pipeline_inputs_ready {
        Some(verify_pipeline(&PipelineInputs {
            schematic: pipeline_targets("schematic"),
            electrical_policy: plan
                .electrical_policy
                .as_ref()
                .map(|_| pipeline_targets("electrical_policy")),
            electrical_review: pipeline_targets("electrical_review"),
            board: pipeline_targets("board"),
            analysis_manifest: pipeline_targets("analysis_manifest"),
            analysis_checks: pipeline_targets("analysis_checks"),
            quality: pipeline_targets("quality"),
            analysis_project: plan
                .analysis_project
                .as_ref()
                .map(|_| pipeline_targets("analysis_project")),
            analysis_rules: plan
                .analysis_rules
                .as_ref()
                .map(|_| pipeline_targets("analysis_rules")),
            analysis_dfm_profile: plan
                .analysis_dfm_profile
                .as_ref()
                .map(|_| pipeline_targets("analysis_dfm_profile")),
            analysis_policy_pack: plan
                .analysis_policy_pack
                .as_ref()
                .map(|_| pipeline_targets("analysis_policy_pack")),
            analysis_physical_profile: plan
                .analysis_physical_profile
                .as_ref()
                .map(|_| pipeline_targets("analysis_physical_profile")),
            manufacturing_package: pipeline_targets("manufacturing_package"),
            firmware_manifest: pipeline_targets("firmware_manifest"),
            factory_receipt: plan
                .factory_receipt
                .as_ref()
                .map(|_| pipeline_targets("factory_receipt")),
            require_factory: plan.require_factory,
        }))
    } else {
        None
    };

    if let (Some(binding_report), Some(pipeline_report)) = (binding.as_ref(), pipeline.as_ref()) {
        match pipeline_report.identities.board_sha256.as_deref() {
            Some(identity) if identity == binding_report.board_source_sha256 => {}
            Some(_) => failures
                .push("identity: binding board SHA-256 does not match pipeline board identity"),
            None => failures.push("identity: pipeline board identity is unavailable"),
        }
        match pipeline_report.identities.schematic_sha256.as_deref() {
            Some(identity)
                if identity == binding_report.circuit_kicad_handoff.schematic_sha256 => {}
            Some(_) => failures.push("identity: binding canonical schematic SHA-256 does not match pipeline schematic identity"),
            None => failures.push("identity: pipeline schematic identity is unavailable"),
        }
    }

    if pipeline.as_ref().is_some_and(|report| !report.passed) {
        let pipeline_report = pipeline.as_ref().expect("pipeline report is present");
        failures.push(format!(
            "pipeline: hardware pipeline gate rejected with {} failure(s)",
            pipeline_report.failures.len()
        ));
    }
    if binding.as_ref().is_some_and(|report| !report.approved) {
        failures.push("binding: circuit-to-KiCad board binding rejected");
    }
    let failures = failures.finish()?;
    let approved = binding.as_ref().is_some_and(|report| report.approved)
        && pipeline.as_ref().is_some_and(|report| report.passed)
        && failures.is_empty();
    let mut report = DeterministicPipelineReport {
        schema_version: REPORT_SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        plan_source_bytes: plan.plan_source_bytes,
        plan_source_sha256: plan.plan_source_sha256.clone(),
        plan_sha256: plan.plan_sha256.clone(),
        input_evidence: evidence,
        binding,
        pipeline,
        failures,
        approved,
        run_sha256: String::new(),
    };
    report.run_sha256 = run_hash(&report)?;
    let serialized =
        serde_json::to_vec(&report).context("serializing deterministic pipeline report")?;
    if serialized.len() > MAX_REPORT_BYTES {
        bail!("deterministic pipeline report exceeds its byte limit");
    }
    Ok(report)
}

fn stage_target(root: &Path, role: &'static str, original: &Path) -> Result<PathBuf> {
    let basename = original
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow!("{role} input path has no basename"))?;
    let directory = root.join(role);
    fs::create_dir_all(&directory)
        .with_context(|| format!("creating private staging directory for {role}"))?;
    Ok(directory.join(basename))
}

fn read_expected(
    role: &str,
    descriptor: &DeterministicPipelineInputDescriptor,
) -> Result<Snapshot, String> {
    reject_symlink_components(&descriptor.path, role)?;
    let bytes = fs::read_with_limit(&descriptor.path, descriptor_limit(role))
        .map_err(|error| format!("{role}: cannot read stable input ({})", error.kind()))?;
    let actual_bytes = bytes.len() as u64;
    let actual_sha = digest_hex(&bytes);
    if actual_bytes != descriptor.bytes {
        return Err(format!(
            "{role}: input byte count does not match its descriptor (expected {}, observed {})",
            descriptor.bytes, actual_bytes
        ));
    }
    if actual_sha != descriptor.sha256 {
        return Err(format!(
            "{role}: input SHA-256 does not match its descriptor"
        ));
    }
    Ok(Snapshot {
        bytes,
        evidence: DeterministicPipelineInputEvidence {
            role: role.to_string(),
            path: descriptor.relative_path.clone(),
            bytes: actual_bytes,
            sha256: actual_sha,
        },
    })
}

fn descriptor_limit(role: &str) -> u64 {
    match role {
        "circuit_spec" => MAX_CIRCUIT_SPEC_BYTES,
        "schematic" => CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES,
        "electrical_policy" => MAX_POLICY_BYTES,
        "electrical_review" => MAX_REVIEW_BYTES,
        "board" => CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES,
        "analysis_manifest"
        | "analysis_checks"
        | "quality"
        | "analysis_project"
        | "analysis_rules"
        | "analysis_dfm_profile"
        | "analysis_policy_pack" => MAX_ANALYSIS_BYTES,
        "analysis_physical_profile" => MAX_PHYSICAL_PROFILE_BYTES,
        "manufacturing_package" => MAX_PACKAGE_BYTES,
        "firmware_manifest" => MAX_FIRMWARE_MANIFEST_BYTES,
        "factory_receipt" => MAX_FACTORY_RECEIPT_BYTES,
        _ => fs::MAX_FILE_BYTES,
    }
}

fn prescan_firmware_bundle(
    plan: &DeterministicPipelinePlan,
    failures: &mut FailureCollector,
) -> Option<BTreeMap<String, Snapshot>> {
    let manifest_path = &plan.firmware_manifest.path;
    if manifest_path.file_name().and_then(|name| name.to_str()) != Some("manifest.json") {
        failures.push("firmware_manifest: firmware manifest filename must be manifest.json");
    }
    let parent = manifest_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if let Err(error) = reject_symlink_components(parent, "firmware_manifest") {
        failures.push(error);
        return None;
    }
    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) => {
            failures.push(format!(
                "firmware_manifest: cannot list firmware bundle directory ({})",
                error.kind()
            ));
            return None;
        }
    };
    let mut actual = Vec::new();
    for entry in entries {
        if actual.len() > FIRMWARE_ARTIFACTS.len() {
            failures.push("firmware_manifest: firmware bundle entry limit exceeded");
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(format!(
                    "firmware_manifest: cannot inspect firmware bundle entry ({})",
                    error.kind()
                ));
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                failures.push(format!(
                    "firmware_manifest: cannot inspect firmware bundle entry type ({})",
                    error.kind()
                ));
                continue;
            }
        };
        if file_type.is_symlink() || !file_type.is_file() {
            failures
                .push("firmware_manifest: firmware bundle contains a non-regular or symlink entry");
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            failures.push("firmware_manifest: firmware bundle contains a non-UTF-8 filename");
            continue;
        };
        actual.push(name);
    }
    actual.sort();
    let mut expected = FIRMWARE_ARTIFACTS
        .iter()
        .map(ToString::to_string)
        .chain(std::iter::once("manifest.json".to_string()))
        .collect::<Vec<_>>();
    expected.sort();
    if actual != expected {
        failures.push("firmware_manifest: firmware bundle must contain exactly manifest.json and the seven fixed artifacts");
    }

    let mut snapshots = BTreeMap::new();
    match read_expected("firmware_manifest", &plan.firmware_manifest) {
        Ok(snapshot) => {
            snapshots.insert("manifest.json".to_string(), snapshot);
        }
        Err(error) => {
            failures.push(error);
        }
    }
    for name in FIRMWARE_ARTIFACTS {
        let path = parent.join(name);
        if let Err(error) = reject_symlink_components(&path, &format!("firmware_artifact:{name}")) {
            failures.push(error);
            continue;
        }
        match fs::read_with_limit(&path, MAX_FIRMWARE_ARTIFACT_BYTES) {
            Ok(bytes) if !bytes.is_empty() => {
                let evidence = DeterministicPipelineInputEvidence {
                    role: format!("firmware_artifact:{name}"),
                    path: plan
                        .firmware_manifest
                        .relative_path
                        .as_str()
                        .rsplit_once('/')
                        .map(|(parent, _)| format!("{parent}/{name}"))
                        .unwrap_or_else(|| name.to_string()),
                    bytes: bytes.len() as u64,
                    sha256: digest_hex(&bytes),
                };
                snapshots.insert(name.to_string(), Snapshot { bytes, evidence });
            }
            Ok(_) => failures.push(format!("firmware_artifact:{name}: input must not be empty")),
            Err(error) => failures.push(format!(
                "firmware_artifact:{name}: cannot read stable input ({})",
                error.kind()
            )),
        }
    }
    match scan_firmware_entries(parent) {
        Ok(actual) if actual == expected => {}
        Ok(_) => failures.push("firmware_manifest: firmware bundle changed during snapshot"),
        Err(error) => failures.push(format!("firmware_manifest: {error}")),
    }
    Some(snapshots)
}

fn scan_firmware_entries(parent: &Path) -> Result<Vec<String>, String> {
    let entries = fs::read_dir(parent)
        .map_err(|error| format!("cannot list firmware bundle directory ({})", error.kind()))?;
    let mut actual = Vec::new();
    for entry in entries {
        if actual.len() > FIRMWARE_ARTIFACTS.len() {
            return Err("firmware bundle entry limit exceeded".into());
        }
        let entry = entry
            .map_err(|error| format!("cannot inspect firmware bundle entry ({})", error.kind()))?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "cannot inspect firmware bundle entry type ({})",
                error.kind()
            )
        })?;
        if file_type.is_symlink() || !file_type.is_file() {
            return Err("firmware bundle contains a non-regular or symlink entry".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "firmware bundle contains a non-UTF-8 filename".to_string())?;
        actual.push(name);
    }
    actual.sort();
    Ok(actual)
}

fn reject_symlink_components(path: &Path, role: &str) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| format!("{role}: cannot resolve current directory: {error}"))?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!("{role}: input path contains a symlink component"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "{role}: cannot inspect input path component ({})",
                    error.kind()
                ));
            }
        }
    }
    Ok(())
}

fn run_hash(report: &DeterministicPipelineReport) -> Result<String> {
    let mut value =
        serde_json::to_value(report).context("serializing deterministic pipeline hash input")?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow!("deterministic pipeline report is not an object"))?;
    object.remove("run_sha256");
    let bytes =
        serde_json::to_vec(&value).context("serializing deterministic pipeline hash bytes")?;
    let mut hasher = Sha256::new();
    hasher.update(RUN_HASH_DOMAIN);
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn bound_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

/// Closed JSON schema for deterministic runner plans.
pub(crate) fn deterministic_pipeline_plan_schema() -> Value {
    let descriptor_ref = |name: &str| json!({"$ref": format!("#/$defs/{name}")});
    let optional_ref = |name: &str| {
        json!({"oneOf": [
            {"type": "null"},
            {"$ref": format!("#/$defs/{name}")}
        ]})
    };
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/deterministic-pipeline-plan-v1.json",
        "title": "pcbex deterministic bounded pipeline plan",
        "type": "object",
        "additionalProperties": false,
        "required": std::iter::once(&"schema_version")
            .chain(ROLE_ORDER.iter())
            .chain(std::iter::once(&"require_factory"))
            .collect::<Vec<_>>(),
        "properties": {
            "schema_version": {"const": PLAN_SCHEMA_VERSION},
            "circuit_spec": descriptor_ref("circuit_spec_descriptor"),
            "schematic": descriptor_ref("schematic_descriptor"),
            "electrical_policy": optional_ref("policy_descriptor"),
            "electrical_review": descriptor_ref("review_descriptor"),
            "board": descriptor_ref("board_descriptor"),
            "analysis_manifest": descriptor_ref("analysis_descriptor"),
            "analysis_checks": descriptor_ref("analysis_descriptor"),
            "quality": descriptor_ref("analysis_descriptor"),
            "analysis_project": optional_ref("analysis_descriptor"),
            "analysis_rules": optional_ref("analysis_descriptor"),
            "analysis_dfm_profile": optional_ref("analysis_descriptor"),
            "analysis_policy_pack": optional_ref("analysis_descriptor"),
            "analysis_physical_profile": optional_ref("physical_profile_descriptor"),
            "manufacturing_package": descriptor_ref("package_descriptor"),
            "firmware_manifest": descriptor_ref("firmware_manifest_descriptor"),
            "factory_receipt": optional_ref("factory_receipt_descriptor"),
            "require_factory": {"type": "boolean"}
        },
        "$defs": {
            "circuit_spec_descriptor": plan_descriptor_schema(MAX_CIRCUIT_SPEC_BYTES),
            "schematic_descriptor": plan_descriptor_schema(CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES),
            "policy_descriptor": plan_descriptor_schema(MAX_POLICY_BYTES),
            "review_descriptor": plan_descriptor_schema(MAX_REVIEW_BYTES),
            "board_descriptor": plan_descriptor_schema(CIRCUIT_KICAD_BOARD_BINDING_MAX_BOARD_BYTES),
            "analysis_descriptor": plan_descriptor_schema(MAX_ANALYSIS_BYTES),
            "physical_profile_descriptor": plan_descriptor_schema(MAX_PHYSICAL_PROFILE_BYTES),
            "package_descriptor": plan_descriptor_schema(MAX_PACKAGE_BYTES),
            "firmware_manifest_descriptor": plan_descriptor_schema(MAX_FIRMWARE_MANIFEST_BYTES),
            "factory_receipt_descriptor": plan_descriptor_schema(MAX_FACTORY_RECEIPT_BYTES)
        }
    })
}

fn plan_descriptor_schema(maximum: u64) -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["path", "bytes", "sha256"],
        "properties": {
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_PLAN_PATH_CHARS,
                "pattern": PORTABLE_PLAN_PATH_PATTERN
            },
            "bytes": {"type": "integer", "minimum": 1, "maximum": maximum},
            "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        }
    })
}

/// Closed JSON schema for deterministic runner reports.
pub(crate) fn deterministic_pipeline_report_schema() -> Value {
    let binding_schema = circuit_kicad_board_binding_report_json_schema();
    let pipeline_v1 = crate::pipeline::pipeline_gate_schema();
    let pipeline_v2 = crate::pipeline::pipeline_factory_gate_schema();
    let mut defs = Map::new();
    insert_prefixed_defs(&mut defs, &binding_schema, "binding_");
    insert_prefixed_defs(&mut defs, &pipeline_v1, "pipeline_v1_");
    insert_prefixed_defs(&mut defs, &pipeline_v2, "pipeline_v2_");
    defs.insert(
        "binding_report".into(),
        closed_nested_report(&binding_schema, "binding_"),
    );
    defs.insert(
        "pipeline_v1_report".into(),
        closed_nested_report(&pipeline_v1, "pipeline_v1_"),
    );
    defs.insert(
        "pipeline_v2_report".into(),
        closed_nested_report(&pipeline_v2, "pipeline_v2_"),
    );
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/deterministic-pipeline-report-v1.json",
        "title": "pcbex deterministic bounded pipeline report",
        "type": "object",
        "additionalProperties": false,
        "required": ["schema_version", "engine_version", "plan_source_bytes", "plan_source_sha256", "plan_sha256", "input_evidence", "binding", "pipeline", "failures", "approved", "run_sha256"],
        "properties": {
            "schema_version": {"const": REPORT_SCHEMA_VERSION},
            "engine_version": {"const": env!("CARGO_PKG_VERSION")},
            "plan_source_bytes": {"type": "integer", "minimum": 1, "maximum": MAX_PLAN_BYTES},
            "plan_source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "plan_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "input_evidence": {
                "type": "array", "minItems": 0, "maxItems": MAX_INPUT_EVIDENCE,
                "items": {"$ref": "#/$defs/input_evidence"}
            },
            "binding": {"oneOf": [{"type": "null"}, {"$ref": "#/$defs/binding_report"}]},
            "pipeline": {"oneOf": [{"type": "null"}, {"oneOf": [{"$ref": "#/$defs/pipeline_v1_report"}, {"$ref": "#/$defs/pipeline_v2_report"}]}]},
            "failures": {"type": "array", "maxItems": MAX_FAILURES, "items": {"type": "string", "minLength": 1, "maxLength": MAX_FAILURE_CHARS}},
            "approved": {"type": "boolean"},
            "run_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
        },
        "$defs": {
            "input_evidence": {
                "type": "object", "additionalProperties": false,
                "required": ["role", "path", "bytes", "sha256"],
                "properties": {
                    "role": {"type": "string", "minLength": 1, "maxLength": 128},
                    "path": {"type": "string", "minLength": 1, "maxLength": MAX_PLAN_PATH_CHARS},
                    "bytes": {"type": "integer", "minimum": 1, "maximum": fs::MAX_FILE_BYTES},
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                }
            }
        },
        "allOf": [{
            "if": {
                "properties": {"approved": {"const": true}},
                "required": ["approved"]
            },
            "then": {
                "properties": {
                    "failures": {"maxItems": 0},
                    "binding": {
                        "allOf": [
                            {"$ref": "#/$defs/binding_report"},
                            {"properties": {"approved": {"const": true}}, "required": ["approved"]}
                        ]
                    },
                    "pipeline": {
                        "oneOf": [
                            {"allOf": [
                                {"$ref": "#/$defs/pipeline_v1_report"},
                                {"properties": {"passed": {"const": true}}, "required": ["passed"]}
                            ]},
                            {"allOf": [
                                {"$ref": "#/$defs/pipeline_v2_report"},
                                {"properties": {"passed": {"const": true}}, "required": ["passed"]}
                            ]}
                        ]
                    }
                }
            },
            "else": {"properties": {"failures": {"minItems": 1}}}
        }]
    });
    if let Some(defs_value) = schema.get_mut("$defs")
        && let Some(defs_object) = defs_value.as_object_mut()
    {
        for (key, value) in defs {
            defs_object.insert(key, value);
        }
    }
    schema
}

fn insert_prefixed_defs(target: &mut Map<String, Value>, schema: &Value, prefix: &str) {
    if let Some(defs) = schema.get("$defs").and_then(Value::as_object) {
        for (name, value) in defs {
            target.insert(
                format!("{prefix}{name}"),
                prefix_refs(value.clone(), prefix),
            );
        }
    }
}

fn closed_nested_report(schema: &Value, prefix: &str) -> Value {
    let mut nested = schema.clone();
    if let Some(object) = nested.as_object_mut() {
        for metadata in ["$schema", "$id", "$defs", "title"] {
            object.remove(metadata);
        }
        object.insert("additionalProperties".into(), Value::Bool(false));
    }
    prefix_refs(nested, prefix)
}

fn prefix_refs(value: Value, prefix: &str) -> Value {
    match value {
        Value::String(reference) if reference.starts_with("#/$defs/") => Value::String(format!(
            "#/$defs/{prefix}{}",
            reference.trim_start_matches("#/$defs/")
        )),
        Value::Array(values) => Value::Array(
            values
                .into_iter()
                .map(|value| prefix_refs(value, prefix))
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| (key, prefix_refs(value, prefix)))
                .collect(),
        ),
        value => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn descriptor(path: &str, bytes: &[u8]) -> Value {
        json!({"path": path, "bytes": bytes.len(), "sha256": digest_hex(bytes)})
    }

    fn plan_json() -> Value {
        json!({
            "schema_version": 1,
            "circuit_spec": descriptor("circuit.json", b"circuit"),
            "schematic": descriptor("design.kicad_sch", b"schematic"),
            "electrical_policy": null,
            "electrical_review": descriptor("review.json", b"review"),
            "board": descriptor("design.kicad_pcb", b"board"),
            "analysis_manifest": descriptor("analysis/run.json", b"manifest"),
            "analysis_checks": descriptor("analysis/checks.json", b"checks"),
            "quality": descriptor("analysis/quality.json", b"quality"),
            "analysis_project": null,
            "analysis_rules": null,
            "analysis_dfm_profile": null,
            "analysis_policy_pack": null,
            "analysis_physical_profile": null,
            "manufacturing_package": descriptor("manufacturing.zip", b"package"),
            "firmware_manifest": descriptor("firmware/manifest.json", b"firmware"),
            "factory_receipt": null,
            "require_factory": false
        })
    }

    #[test]
    fn parser_requires_explicit_optional_nulls_and_rejects_parent_paths() {
        let workspace = tempfile::tempdir().unwrap();
        let plan_path = workspace.path().join("plan.json");
        fs::write(&plan_path, serde_json::to_vec(&plan_json()).unwrap()).unwrap();
        let plan = load_deterministic_pipeline_plan(&plan_path).unwrap();
        assert_eq!(
            plan.schematic.path,
            workspace.path().join("design.kicad_sch")
        );

        let mut missing = plan_json();
        missing.as_object_mut().unwrap().remove("analysis_rules");
        fs::write(&plan_path, serde_json::to_vec(&missing).unwrap()).unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());

        let mut parent = plan_json();
        parent["board"]["path"] = Value::String("../board.kicad_pcb".into());
        fs::write(&plan_path, serde_json::to_vec(&parent).unwrap()).unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());
    }

    #[test]
    fn parser_rejects_duplicate_keys_paths_and_non_portable_names() {
        let workspace = tempfile::tempdir().unwrap();
        let plan_path = workspace.path().join("plan.json");
        let rendered = serde_json::to_string(&plan_json()).unwrap();
        let duplicate_key = rendered.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        fs::write(&plan_path, duplicate_key).unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());

        let mut duplicate_path = plan_json();
        duplicate_path["board"]["path"] = duplicate_path["schematic"]["path"].clone();
        fs::write(&plan_path, serde_json::to_vec(&duplicate_path).unwrap()).unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());

        let mut case_folded_duplicate = plan_json();
        case_folded_duplicate["board"]["path"] = Value::String("DESIGN.KICAD_SCH".into());
        fs::write(
            &plan_path,
            serde_json::to_vec(&case_folded_duplicate).unwrap(),
        )
        .unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());

        let mut derived_firmware_duplicate = plan_json();
        derived_firmware_duplicate["board"]["path"] = Value::String("firmware/HOST.PY".into());
        fs::write(
            &plan_path,
            serde_json::to_vec(&derived_firmware_duplicate).unwrap(),
        )
        .unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());

        for unsafe_path in [
            "C:/board.kicad_pcb",
            "hardware\\board.kicad_pcb",
            "hardware//board.kicad_pcb",
            "hardware/./board.kicad_pcb",
            "hardware/board.kicad_pcb/",
            "hardware/board\nkicad_pcb",
            "hardware/NUL.json",
            "hardware/COM1",
            "hardware/name.",
            "hardware/name ",
            "hardware/a*b",
        ] {
            let mut plan = plan_json();
            plan["board"]["path"] = Value::String(unsafe_path.into());
            fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
            assert!(
                load_deterministic_pipeline_plan(&plan_path).is_err(),
                "unsafe path was accepted: {unsafe_path:?}"
            );
        }

        let mut oversized_component = plan_json();
        oversized_component["board"]["path"] = Value::String(format!("{}.json", "a".repeat(256)));
        fs::write(
            &plan_path,
            serde_json::to_vec(&oversized_component).unwrap(),
        )
        .unwrap();
        assert!(load_deterministic_pipeline_plan(&plan_path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn parser_rejects_a_symlinked_plan() {
        use std::os::unix::fs::symlink;

        let workspace = tempfile::tempdir().unwrap();
        let plan_path = workspace.path().join("plan.json");
        let link_path = workspace.path().join("plan-link.json");
        fs::write(&plan_path, serde_json::to_vec(&plan_json()).unwrap()).unwrap();
        symlink(&plan_path, &link_path).unwrap();
        assert!(load_deterministic_pipeline_plan(&link_path).is_err());
    }

    #[test]
    fn input_paths_include_firmware_artifacts_in_fixed_order() {
        let workspace = tempfile::tempdir().unwrap();
        let plan_path = workspace.path().join("plan.json");
        fs::write(&plan_path, serde_json::to_vec(&plan_json()).unwrap()).unwrap();
        let plan = load_deterministic_pipeline_plan(&plan_path).unwrap();
        let paths = plan.input_paths();
        assert_eq!(paths.len(), 9 + FIRMWARE_ARTIFACTS.len());
        assert_eq!(paths[0], workspace.path().join("circuit.json"));
        assert_eq!(
            paths.last().unwrap(),
            &workspace.path().join("firmware/host.py")
        );
    }

    #[test]
    fn schemas_are_closed_and_require_every_role() {
        let plan = deterministic_pipeline_plan_schema();
        assert_eq!(plan["additionalProperties"], false);
        assert!(
            plan["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "analysis_physical_profile")
        );
        assert!(
            plan["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == "schema_version")
        );
        assert_eq!(
            plan["$defs"]["circuit_spec_descriptor"]["properties"]["bytes"]["maximum"],
            MAX_CIRCUIT_SPEC_BYTES
        );
        assert_eq!(
            plan["$defs"]["physical_profile_descriptor"]["properties"]["bytes"]["maximum"],
            MAX_PHYSICAL_PROFILE_BYTES
        );
        let report = deterministic_pipeline_report_schema();
        assert_eq!(report["additionalProperties"], false);
        assert!(report["$defs"]["binding_report"]["additionalProperties"] == false);
        assert!(report["$defs"]["pipeline_v1_report"]["allOf"].is_array());
        assert!(report["$defs"]["pipeline_v2_report"]["allOf"].is_array());
        assert_eq!(
            report["properties"]["engine_version"]["const"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            report["allOf"][0]["else"]["properties"]["failures"]["minItems"],
            1
        );
    }
}
