//! Compile a closed high-level deterministic-pipeline intent into a plan.
//!
//! The runner consumes an explicit plan containing byte/SHA-256 descriptors,
//! while callers usually have only the source paths.  This module is the
//! narrow, side-effect-free bridge between those contracts: it reads a closed
//! intent, computes every descriptor from bounded stable bytes, enforces the
//! runner's fixed eight-file firmware bundle boundary, renders the existing
//! plan-v1 wire shape, and reparses the rendered bytes through the runner's
//! authoritative validator. It performs no open-ended discovery, invokes no
//! child or network service, and never writes the destination.

use crate::bounded_io as fs;
use crate::deterministic_pipeline_runner::{
    DeterministicFirmwareBundleSnapshot, DeterministicPipelinePlan, MAX_PLAN_BYTES,
    MAX_PLAN_PATH_CHARS, MAX_TOTAL_INPUT_BYTES, PLAN_SCHEMA_VERSION, PORTABLE_PLAN_PATH_PATTERN,
    ROLE_ORDER, descriptor_limit, load_deterministic_pipeline_plan,
    preflight_deterministic_firmware_bundle, reject_duplicate_json_keys, reject_symlink_components,
    validate_relative_path,
};
use crate::firmware::{FIRMWARE_ARTIFACTS, FirmwareManifest};
use crate::manufacturing_limits::portable_manufacturing_name_key;
use crate::pipeline::validate_firmware_manifest;
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Maximum bytes accepted for a compiler intent.  Keep the source boundary
/// equal to the existing plan boundary so a generated plan can always be
/// revalidated under the runner's limits.
pub(crate) const MAX_INTENT_BYTES: u64 = MAX_PLAN_BYTES;

const OPTIONAL_ROLES: [&str; 7] = [
    "electrical_policy",
    "analysis_project",
    "analysis_rules",
    "analysis_dfm_profile",
    "analysis_policy_pack",
    "analysis_physical_profile",
    "factory_receipt",
];

/// Result returned by [`compile_deterministic_pipeline_plan`].
///
/// The compiler does not publish the plan.  The CLI owns no-clobber
/// reservation and atomic publication after receiving these bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CompiledDeterministicPipelinePlan {
    pub(crate) plan_bytes: Vec<u8>,
    pub(crate) intent_source_bytes: u64,
    pub(crate) intent_source_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIntent {
    schema_version: u32,
    circuit_spec: String,
    schematic: String,
    electrical_policy: Option<Option<String>>,
    electrical_review: String,
    board: String,
    analysis_manifest: String,
    analysis_checks: String,
    quality: String,
    analysis_project: Option<Option<String>>,
    analysis_rules: Option<Option<String>>,
    analysis_dfm_profile: Option<Option<String>>,
    analysis_policy_pack: Option<Option<String>>,
    analysis_physical_profile: Option<Option<String>>,
    manufacturing_package: String,
    firmware_manifest: String,
    factory_receipt: Option<Option<String>>,
    require_factory: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct WireDescriptor {
    path: String,
    bytes: u64,
    sha256: String,
}

/// The output wire shape intentionally mirrors the existing runner plan.  Do
/// not add compiler metadata here: consumers must continue to parse this as
/// `deterministic-pipeline-plan-v1`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct WirePlan {
    schema_version: u32,
    circuit_spec: WireDescriptor,
    schematic: WireDescriptor,
    electrical_policy: Option<WireDescriptor>,
    electrical_review: WireDescriptor,
    board: WireDescriptor,
    analysis_manifest: WireDescriptor,
    analysis_checks: WireDescriptor,
    quality: WireDescriptor,
    analysis_project: Option<WireDescriptor>,
    analysis_rules: Option<WireDescriptor>,
    analysis_dfm_profile: Option<WireDescriptor>,
    analysis_policy_pack: Option<WireDescriptor>,
    analysis_physical_profile: Option<WireDescriptor>,
    manufacturing_package: WireDescriptor,
    firmware_manifest: WireDescriptor,
    factory_receipt: Option<WireDescriptor>,
    require_factory: bool,
}

/// Return the closed schema for compiler intents.
pub(crate) fn deterministic_pipeline_intent_schema() -> Value {
    let path = json!({
        "type": "string",
        "minLength": 1,
        "maxLength": MAX_PLAN_PATH_CHARS,
        "pattern": PORTABLE_PLAN_PATH_PATTERN,
    });
    let optional_path = json!({
        "oneOf": [
            {"type": "null"},
            path.clone(),
        ]
    });
    let mut properties = Map::new();
    properties.insert(
        "schema_version".into(),
        json!({"const": PLAN_SCHEMA_VERSION}),
    );
    for role in ROLE_ORDER {
        properties.insert(
            role.into(),
            if OPTIONAL_ROLES.contains(&role) {
                optional_path.clone()
            } else {
                path.clone()
            },
        );
    }
    properties.insert("require_factory".into(), json!({"type": "boolean"}));
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/pcbex/schemas/deterministic-pipeline-intent-v1.json",
        "title": "pcbex deterministic pipeline plan compiler intent",
        "type": "object",
        "additionalProperties": false,
        "required": std::iter::once("schema_version")
            .chain(ROLE_ORDER.iter().copied())
            .chain(std::iter::once("require_factory"))
            .collect::<Vec<_>>(),
        "properties": properties,
    })
}

/// Compile one closed intent into the existing deterministic plan-v1 bytes.
///
/// Intent paths are interpreted relative to the canonical parent directory of
/// `output_path`, matching the runner's plan-relative path semantics.  The
/// destination is inspected but not created or replaced; callers should
/// reserve it immediately before publishing `plan_bytes`.
pub(crate) fn compile_deterministic_pipeline_plan(
    intent_path: &Path,
    output_path: &Path,
) -> Result<CompiledDeterministicPipelinePlan> {
    let output_parent = resolve_output_parent(output_path)?;
    let output_destination = output_parent.join(
        output_path
            .file_name()
            .ok_or_else(|| anyhow!("deterministic pipeline plan output must name a file"))?,
    );
    let intent_identity = resolve_existing_file(intent_path, "deterministic pipeline intent")?;
    if path_key(&output_destination) == path_key(&intent_identity) {
        bail!("deterministic pipeline plan output must not alias its intent")
    }

    let intent_bytes = fs::read_with_limit(intent_path, MAX_INTENT_BYTES).with_context(|| {
        format!(
            "reading deterministic pipeline intent {}",
            intent_path.display()
        )
    })?;
    let intent_source_sha256 = digest_hex(&intent_bytes);
    let intent = parse_intent(&intent_bytes, intent_path)?;
    if intent.schema_version != PLAN_SCHEMA_VERSION {
        bail!(
            "unsupported deterministic pipeline intent schema version {}",
            intent.schema_version
        );
    }

    let mut seen_paths = BTreeSet::new();
    let mut aggregate_bytes = 0_u64;
    let circuit_spec = compile_descriptor(
        "circuit_spec",
        &intent.circuit_spec,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let schematic = compile_descriptor(
        "schematic",
        &intent.schematic,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let electrical_policy = compile_optional_descriptor(
        "electrical_policy",
        intent.electrical_policy,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let electrical_review = compile_descriptor(
        "electrical_review",
        &intent.electrical_review,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let board = compile_descriptor(
        "board",
        &intent.board,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_manifest = compile_descriptor(
        "analysis_manifest",
        &intent.analysis_manifest,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_checks = compile_descriptor(
        "analysis_checks",
        &intent.analysis_checks,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let quality = compile_descriptor(
        "quality",
        &intent.quality,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_project = compile_optional_descriptor(
        "analysis_project",
        intent.analysis_project,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_rules = compile_optional_descriptor(
        "analysis_rules",
        intent.analysis_rules,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_dfm_profile = compile_optional_descriptor(
        "analysis_dfm_profile",
        intent.analysis_dfm_profile,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_policy_pack = compile_optional_descriptor(
        "analysis_policy_pack",
        intent.analysis_policy_pack,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let analysis_physical_profile = compile_optional_descriptor(
        "analysis_physical_profile",
        intent.analysis_physical_profile,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let manufacturing_package = compile_descriptor(
        "manufacturing_package",
        &intent.manufacturing_package,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let firmware_manifest = compile_descriptor(
        "firmware_manifest",
        &intent.firmware_manifest,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;
    let factory_receipt = compile_optional_descriptor(
        "factory_receipt",
        intent.factory_receipt,
        &output_parent,
        &output_destination,
        &mut seen_paths,
        &mut aggregate_bytes,
    )?;

    let firmware_parent = Path::new(&firmware_manifest.path)
        .parent()
        .map(|parent| output_parent.join(parent))
        .unwrap_or_else(|| output_parent.clone());
    if path_key(&output_parent) == path_key(&firmware_parent) {
        bail!("deterministic pipeline plan output must be outside the firmware bundle directory")
    }

    let wire = WirePlan {
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
        require_factory: intent.require_factory,
    };
    let mut plan_bytes =
        serde_json::to_vec(&wire).context("serializing deterministic pipeline plan")?;
    plan_bytes.push(b'\n');
    if plan_bytes.len() as u64 > MAX_PLAN_BYTES {
        bail!("compiled deterministic pipeline plan exceeds its byte limit")
    }
    let rendered_plan = validate_rendered_plan(&plan_bytes, &output_parent)?;
    let firmware_bundle = validate_compiler_firmware_bundle(&rendered_plan)?;
    let firmware_artifact_bytes = firmware_bundle
        .entries
        .iter()
        .filter(|(name, _)| name.as_str() != "manifest.json")
        .try_fold(0_u64, |total, (_, identity)| {
            total
                .checked_add(identity.bytes)
                .ok_or_else(|| anyhow!("deterministic firmware artifact byte count overflow"))
        })?;
    aggregate_bytes = aggregate_bytes
        .checked_add(firmware_artifact_bytes)
        .ok_or_else(|| anyhow!("deterministic pipeline input byte count overflow"))?;
    if aggregate_bytes > MAX_TOTAL_INPUT_BYTES {
        bail!("deterministic pipeline inputs exceed the aggregate byte limit")
    }
    confirm_wire_sources(&wire, &output_parent)?;
    confirm_intent_unchanged(
        intent_path,
        &intent_identity,
        &intent_bytes,
        &intent_source_sha256,
    )?;
    // Keep the exact-eight resnapshot as the final source read before
    // returning canonical plan bytes. The CLI still owns no-clobber
    // publication, and the runner independently reopens the bundle later.
    if validate_compiler_firmware_bundle(&rendered_plan)? != firmware_bundle {
        bail!("firmware bundle changed during deterministic pipeline compilation")
    }

    Ok(CompiledDeterministicPipelinePlan {
        plan_bytes,
        intent_source_bytes: intent_bytes.len() as u64,
        intent_source_sha256,
    })
}

/// Re-read every source after rendering and runner validation.  The generated
/// descriptor is only trustworthy if the bounded source bytes still agree at
/// the end of compilation; otherwise a concurrent writer could make the
/// published plan describe bytes that were never validated together.
fn confirm_wire_sources(wire: &WirePlan, output_parent: &Path) -> Result<()> {
    for (role, descriptor) in [
        ("circuit_spec", &wire.circuit_spec),
        ("schematic", &wire.schematic),
        ("electrical_review", &wire.electrical_review),
        ("board", &wire.board),
        ("analysis_manifest", &wire.analysis_manifest),
        ("analysis_checks", &wire.analysis_checks),
        ("quality", &wire.quality),
        ("manufacturing_package", &wire.manufacturing_package),
        ("firmware_manifest", &wire.firmware_manifest),
    ] {
        confirm_descriptor_source(role, descriptor, output_parent)?;
    }
    for (role, descriptor) in [
        ("electrical_policy", wire.electrical_policy.as_ref()),
        ("analysis_project", wire.analysis_project.as_ref()),
        ("analysis_rules", wire.analysis_rules.as_ref()),
        ("analysis_dfm_profile", wire.analysis_dfm_profile.as_ref()),
        ("analysis_policy_pack", wire.analysis_policy_pack.as_ref()),
        (
            "analysis_physical_profile",
            wire.analysis_physical_profile.as_ref(),
        ),
        ("factory_receipt", wire.factory_receipt.as_ref()),
    ] {
        if let Some(descriptor) = descriptor {
            confirm_descriptor_source(role, descriptor, output_parent)?;
        }
    }
    Ok(())
}

fn confirm_descriptor_source(
    role: &str,
    descriptor: &WireDescriptor,
    output_parent: &Path,
) -> Result<()> {
    let path = output_parent.join(&descriptor.path);
    reject_symlink_components(&path, role).map_err(anyhow::Error::msg)?;
    let bytes = fs::read_with_limit(&path, descriptor_limit(role))
        .with_context(|| format!("rereading bounded {role} input {}", path.display()))?;
    let observed_bytes = bytes.len() as u64;
    let observed_sha256 = digest_hex(&bytes);
    if observed_bytes != descriptor.bytes || observed_sha256 != descriptor.sha256 {
        bail!("{role} input changed during deterministic pipeline compilation")
    }
    Ok(())
}

fn confirm_intent_unchanged(
    intent_path: &Path,
    initial_identity: &Path,
    initial_bytes: &[u8],
    initial_sha256: &str,
) -> Result<()> {
    let current_identity = resolve_existing_file(intent_path, "deterministic pipeline intent")?;
    if path_key(&current_identity) != path_key(initial_identity) {
        bail!("deterministic pipeline intent path changed during compilation")
    }
    let current_bytes =
        fs::read_with_limit(&current_identity, MAX_INTENT_BYTES).with_context(|| {
            format!(
                "rereading deterministic pipeline intent {}",
                intent_path.display()
            )
        })?;
    if current_bytes != initial_bytes || digest_hex(&current_bytes) != initial_sha256 {
        bail!("deterministic pipeline intent changed during compilation")
    }
    Ok(())
}

fn validate_compiler_firmware_bundle(
    plan: &DeterministicPipelinePlan,
) -> Result<DeterministicFirmwareBundleSnapshot> {
    let snapshot = preflight_deterministic_firmware_bundle(plan)?;
    reject_duplicate_json_keys(&snapshot.manifest_bytes)
        .context("parsing deterministic firmware bundle manifest")?;
    let manifest: FirmwareManifest = serde_json::from_slice(&snapshot.manifest_bytes)
        .context("parsing deterministic firmware bundle manifest")?;
    validate_firmware_manifest(&manifest)
        .map_err(anyhow::Error::msg)
        .context("validating deterministic firmware bundle manifest")?;
    for descriptor in &manifest.artifacts {
        let observed = snapshot.entries.get(&descriptor.path).ok_or_else(|| {
            anyhow!(
                "deterministic firmware bundle preflight did not capture {}",
                descriptor.path
            )
        })?;
        if observed.bytes != descriptor.bytes || observed.sha256 != descriptor.sha256 {
            bail!(
                "firmware artifact {} does not match its manifest bytes/SHA-256 descriptor",
                descriptor.path
            )
        }
    }
    if snapshot.entries.len() != FIRMWARE_ARTIFACTS.len() + 1 {
        bail!("deterministic firmware bundle preflight did not capture exactly eight files")
    }
    Ok(snapshot)
}

fn compile_optional_descriptor(
    role: &str,
    descriptor: Option<Option<String>>,
    output_parent: &Path,
    output_destination: &Path,
    seen_paths: &mut BTreeSet<String>,
    aggregate_bytes: &mut u64,
) -> Result<Option<WireDescriptor>> {
    match descriptor {
        Some(Some(path)) => compile_descriptor(
            role,
            &path,
            output_parent,
            output_destination,
            seen_paths,
            aggregate_bytes,
        )
        .map(Some),
        Some(None) => Ok(None),
        // `parse_intent` checks object membership before deserialization.  A
        // serde nested option decodes an explicit JSON `null` as `None`, so
        // this arm is the valid null form rather than a missing key.
        None => Ok(None),
    }
}

fn compile_descriptor(
    role: &str,
    relative_path: &str,
    output_parent: &Path,
    output_destination: &Path,
    seen_paths: &mut BTreeSet<String>,
    aggregate_bytes: &mut u64,
) -> Result<WireDescriptor> {
    validate_relative_path(relative_path, role)?;
    let key = portable_manufacturing_name_key(relative_path);
    if !seen_paths.insert(key) {
        bail!("deterministic pipeline intent descriptors must not reuse the same path")
    }
    let path = output_parent.join(relative_path);
    if path_key(&path) == path_key(output_destination) {
        bail!("{role} input must not alias the deterministic pipeline plan output")
    }
    reject_symlink_components(&path, role).map_err(anyhow::Error::msg)?;
    let bytes = fs::read_with_limit(&path, descriptor_limit(role))
        .with_context(|| format!("reading bounded {role} input {}", path.display()))?;
    if bytes.is_empty() {
        bail!("{role} input must not be empty")
    }
    *aggregate_bytes = aggregate_bytes
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| anyhow!("deterministic pipeline input byte count overflow"))?;
    if *aggregate_bytes > MAX_TOTAL_INPUT_BYTES {
        bail!("deterministic pipeline inputs exceed the aggregate byte limit")
    }
    Ok(WireDescriptor {
        path: relative_path.to_string(),
        bytes: bytes.len() as u64,
        sha256: digest_hex(&bytes),
    })
}

fn parse_intent(source: &[u8], path: &Path) -> Result<WireIntent> {
    reject_duplicate_json_keys(source)
        .with_context(|| format!("parsing deterministic pipeline intent {}", path.display()))?;
    let value: Value = serde_json::from_slice(source)
        .with_context(|| format!("parsing deterministic pipeline intent {}", path.display()))?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("deterministic pipeline intent must be a JSON object"))?;
    for key in std::iter::once("schema_version")
        .chain(ROLE_ORDER.iter().copied())
        .chain(std::iter::once("require_factory"))
    {
        if !object.contains_key(key) {
            bail!("deterministic pipeline intent is missing required key {key}")
        }
    }
    serde_json::from_value(value).context("decoding deterministic pipeline intent")
}

fn resolve_output_parent(output_path: &Path) -> Result<PathBuf> {
    reject_symlink_components(output_path, "deterministic pipeline plan output")
        .map_err(anyhow::Error::msg)?;
    let parent = output_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "resolving deterministic pipeline plan output directory {}",
            parent.display()
        )
    })?;
    if !fs::symlink_metadata(&parent)?.is_dir() {
        bail!("deterministic pipeline plan output parent is not a directory")
    }
    match fs::symlink_metadata(output_path) {
        Ok(_) => bail!(
            "refusing to overwrite existing deterministic pipeline plan output {}",
            output_path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting deterministic pipeline plan output {}",
                    output_path.display()
                )
            });
        }
    }
    Ok(parent)
}

fn resolve_existing_file(path: &Path, role: &str) -> Result<PathBuf> {
    reject_symlink_components(path, role).map_err(anyhow::Error::msg)?;
    let canonical =
        fs::canonicalize(path).with_context(|| format!("resolving {role} {}", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical)
        .with_context(|| format!("inspecting {role} {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("{role} must be a regular file")
    }
    Ok(canonical)
}

fn validate_rendered_plan(
    plan_bytes: &[u8],
    output_parent: &Path,
) -> Result<DeterministicPipelinePlan> {
    let mut temporary = tempfile::Builder::new()
        .prefix(".pcbex-compiled-plan-")
        .tempfile_in(output_parent)
        .context("creating temporary deterministic pipeline plan validation file")?;
    temporary
        .write_all(plan_bytes)
        .context("writing temporary deterministic pipeline plan validation file")?;
    temporary
        .flush()
        .context("flushing temporary deterministic pipeline plan validation file")?;
    load_deterministic_pipeline_plan(temporary.path())
        .context("revalidating compiled deterministic pipeline plan")
}

fn path_key(path: &Path) -> String {
    portable_manufacturing_name_key(&path.to_string_lossy())
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn intent_json() -> Value {
        json!({
            "schema_version": 1,
            "circuit_spec": "circuit.json",
            "schematic": "design.kicad_sch",
            "electrical_policy": null,
            "electrical_review": "review.json",
            "board": "design.kicad_pcb",
            "analysis_manifest": "analysis/run.json",
            "analysis_checks": "analysis/checks.json",
            "quality": "analysis/quality.json",
            "analysis_project": null,
            "analysis_rules": null,
            "analysis_dfm_profile": null,
            "analysis_policy_pack": null,
            "analysis_physical_profile": null,
            "manufacturing_package": "manufacturing.zip",
            "firmware_manifest": "firmware/manifest.json",
            "factory_receipt": null,
            "require_factory": false
        })
    }

    fn write_fixture(root: &Path) {
        for (path, bytes) in [
            ("circuit.json", b"circuit".as_slice()),
            ("design.kicad_sch", b"schematic".as_slice()),
            ("review.json", b"review".as_slice()),
            ("design.kicad_pcb", b"board".as_slice()),
            ("analysis/run.json", b"manifest".as_slice()),
            ("analysis/checks.json", b"checks".as_slice()),
            ("analysis/quality.json", b"quality".as_slice()),
            ("manufacturing.zip", b"package".as_slice()),
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, bytes).unwrap();
        }
        write_firmware_bundle(root);
    }

    fn skipped_build(command: &str) -> Value {
        json!({
            "attempted": false,
            "passed": false,
            "command": [command],
            "exit_code": null,
            "smoke": {
                "attempted": false,
                "passed": false,
                "command": ["smoke"],
                "exit_code": null
            }
        })
    }

    fn write_firmware_bundle(root: &Path) {
        let firmware = root.join("firmware");
        fs::create_dir_all(&firmware).unwrap();
        let artifacts = FIRMWARE_ARTIFACTS
            .iter()
            .map(|name| {
                let bytes = name.as_bytes();
                fs::write(firmware.join(name), bytes).unwrap();
                json!({
                    "path": name,
                    "bytes": bytes.len(),
                    "sha256": digest_hex(bytes)
                })
            })
            .collect::<Vec<_>>();
        let manifest = json!({
            "schema_version": 2,
            "engine": "pcbex",
            "engine_version": env!("CARGO_PKG_VERSION"),
            "schematic_sha256": "a".repeat(64),
            "artifacts": artifacts,
            "c_build": skipped_build("cc"),
            "cpp_build": skipped_build("c++"),
            "python_check": skipped_build("python3")
        });
        fs::write(
            firmware.join("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn compiles_digest_bound_plan_and_revalidates_it() {
        let directory = tempfile::tempdir().unwrap();
        write_fixture(directory.path());
        let intent = directory.path().join("intent.json");
        fs::write(&intent, serde_json::to_vec(&intent_json()).unwrap()).unwrap();
        let output = directory.path().join("pipeline-plan.json");
        let compiled = compile_deterministic_pipeline_plan(&intent, &output).unwrap();
        assert_eq!(
            compiled.intent_source_bytes,
            fs::metadata(&intent).unwrap().len()
        );
        assert_eq!(compiled.plan_bytes.last(), Some(&b'\n'));
        fs::write(&output, &compiled.plan_bytes).unwrap();
        let plan = load_deterministic_pipeline_plan(&output).unwrap();
        assert_eq!(plan.schematic.bytes, b"schematic".len() as u64);
        assert_eq!(plan.schematic.sha256, digest_hex(b"schematic"));
    }

    #[test]
    fn compiler_applies_the_dedicated_dfm_profile_descriptor_limit() {
        let directory = tempfile::tempdir().unwrap();
        write_fixture(directory.path());
        let profile = directory.path().join("analysis/dfm-profile.json");
        fs::write(&profile, vec![b'x'; pcbex_core::MAX_DFM_PROFILE_TEXT_BYTES]).unwrap();
        let intent = directory.path().join("intent.json");
        let mut intent_value = intent_json();
        intent_value["analysis_dfm_profile"] = Value::String("analysis/dfm-profile.json".into());
        fs::write(&intent, serde_json::to_vec(&intent_value).unwrap()).unwrap();
        let output = directory.path().join("pipeline-plan.json");
        assert!(compile_deterministic_pipeline_plan(&intent, &output).is_ok());

        fs::write(
            &profile,
            vec![b'x'; pcbex_core::MAX_DFM_PROFILE_TEXT_BYTES + 1],
        )
        .unwrap();
        let error = compile_deterministic_pipeline_plan(&intent, &output).unwrap_err();
        assert!(error.to_string().contains("analysis_dfm_profile"));
    }

    #[test]
    fn output_is_deterministic_and_rejects_existing_destinations() {
        let directory = tempfile::tempdir().unwrap();
        write_fixture(directory.path());
        let intent = directory.path().join("intent.json");
        fs::write(&intent, serde_json::to_vec(&intent_json()).unwrap()).unwrap();
        let first =
            compile_deterministic_pipeline_plan(&intent, &directory.path().join("first-plan.json"))
                .unwrap();
        let second = compile_deterministic_pipeline_plan(
            &intent,
            &directory.path().join("second-plan.json"),
        )
        .unwrap();
        assert_eq!(first.plan_bytes, second.plan_bytes);
        let existing = directory.path().join("existing-plan.json");
        fs::write(&existing, b"old").unwrap();
        assert!(compile_deterministic_pipeline_plan(&intent, &existing).is_err());
    }

    #[test]
    fn rejects_duplicate_keys_paths_and_unsafe_destinations() {
        let directory = tempfile::tempdir().unwrap();
        write_fixture(directory.path());
        let intent = directory.path().join("intent.json");
        let mut duplicate = serde_json::to_string(&intent_json()).unwrap();
        duplicate = duplicate.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        );
        fs::write(&intent, duplicate).unwrap();
        assert!(
            compile_deterministic_pipeline_plan(&intent, &directory.path().join("plan.json"))
                .is_err()
        );

        let mut unsafe_intent = intent_json();
        unsafe_intent["board"] = Value::String("../board.kicad_pcb".into());
        fs::write(&intent, serde_json::to_vec(&unsafe_intent).unwrap()).unwrap();
        assert!(
            compile_deterministic_pipeline_plan(&intent, &directory.path().join("plan.json"))
                .is_err()
        );

        fs::write(&intent, serde_json::to_vec(&intent_json()).unwrap()).unwrap();
        assert!(compile_deterministic_pipeline_plan(&intent, &intent).is_err());
    }

    #[test]
    fn rejects_plan_output_inside_firmware_bundle() {
        let directory = tempfile::tempdir().unwrap();
        write_fixture(directory.path());
        let intent = directory.path().join("intent.json");
        fs::write(&intent, serde_json::to_vec(&intent_json()).unwrap()).unwrap();
        let mut nested = intent_json();
        nested["firmware_manifest"] = Value::String("manifest.json".into());
        let firmware_intent = directory.path().join("firmware-intent.json");
        fs::write(&firmware_intent, serde_json::to_vec(&nested).unwrap()).unwrap();
        assert!(
            compile_deterministic_pipeline_plan(
                &firmware_intent,
                &directory.path().join("firmware/plan.json")
            )
            .is_err()
        );
    }
}
