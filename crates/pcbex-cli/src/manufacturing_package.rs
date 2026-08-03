//! Factory-ready BOM, pick-and-place, manifest, and archive generation.

use crate::bounded_io::{opened_path_matches, same_file};
use crate::manufacturing_limits::{
    ManufacturingLimits, portable_manufacturing_name_key, scan_manufacturing_workspace,
    validate_manufacturing_basename,
};
use anyhow::{Context, Result, bail};
use pcbex_kicad::ManufacturingPart;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const MANIFEST_NAME: &str = "manifest.json";
const ARCHIVE_NAME: &str = "manufacturing.zip";
const GENERATED_CSV_NAMES: [&str; 2] = ["bom.csv", "cpl.csv"];
const MAX_NORMALIZATION_LINE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
struct ArtifactDescriptor {
    path: String,
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct ManufacturingManifest {
    schema_version: u32,
    engine: &'static str,
    engine_version: &'static str,
    tools: KiCadIdentity,
    input: ArtifactDescriptor,
    project_inputs: Vec<ArtifactDescriptor>,
    parts: ManufacturingCounts,
    artifacts: Vec<ArtifactDescriptor>,
    archive: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct KiCadIdentity {
    #[serde(rename = "kicad_cli")]
    pub version: String,
    #[serde(rename = "kicad_cli_about_sha256")]
    pub about_sha256: String,
}

#[derive(Clone, Debug)]
pub struct KiCadProjectInput {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct ManufacturingCounts {
    total: usize,
    bom: usize,
    placement: usize,
    dnp: usize,
}

/// Write all deterministic, vendor-neutral manufacturing deliverables.
pub fn write_manufacturing_package(
    output_dir: &Path,
    input_path: &Path,
    input_bytes: &[u8],
    project_inputs: &[KiCadProjectInput],
    parts: &[ManufacturingPart],
    exported_artifacts: &[PathBuf],
    kicad_identity: &KiCadIdentity,
) -> Result<PathBuf> {
    write_manufacturing_package_with_limits(
        output_dir,
        input_path,
        input_bytes,
        project_inputs,
        parts,
        exported_artifacts,
        kicad_identity,
        ManufacturingLimits::production(),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_manufacturing_package_with_limits(
    output_dir: &Path,
    input_path: &Path,
    input_bytes: &[u8],
    project_inputs: &[KiCadProjectInput],
    parts: &[ManufacturingPart],
    exported_artifacts: &[PathBuf],
    kicad_identity: &KiCadIdentity,
    limits: ManufacturingLimits,
) -> Result<PathBuf> {
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    let input_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("manufacturing input must have a UTF-8 filename"))?;
    validate_portable_name(input_name, limits, "manufacturing input")?;
    ensure_slice_within_file_limit(input_bytes, limits, "manufacturing input")?;
    validate_kicad_identity(kicad_identity)?;
    let mut files = validate_exported_artifacts(output_dir, exported_artifacts, limits)?;
    if !files
        .iter()
        .any(|path| path.file_name().and_then(|name| name.to_str()) == Some("drc.rpt"))
    {
        bail!("manufacturing package requires the generated drc.rpt artifact");
    }
    let mut input_names = BTreeSet::from([portable_manufacturing_name_key(input_name)]);
    let mut project_input_descriptors = Vec::with_capacity(project_inputs.len());
    for project_input in project_inputs {
        let name = project_input
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("KiCad project input must have a UTF-8 filename"))?;
        validate_portable_name(name, limits, "KiCad project input")?;
        ensure_slice_within_file_limit(&project_input.bytes, limits, "KiCad project input")?;
        if !input_names.insert(portable_manufacturing_name_key(name)) {
            bail!("duplicate KiCad manufacturing input filename {name}");
        }
        project_input_descriptors.push(descriptor_for_bytes(name, &project_input.bytes));
    }
    project_input_descriptors.sort_by(|left, right| left.path.cmp(&right.path));

    let archive_entries = files
        .len()
        .checked_add(GENERATED_CSV_NAMES.len() + 1)
        .ok_or_else(|| anyhow::anyhow!("manufacturing archive entry count overflow"))?;
    if archive_entries > limits.max_entries {
        bail!(
            "manufacturing archive contains more than {} entries",
            limits.max_entries
        );
    }

    for name in GENERATED_CSV_NAMES {
        let path = output_dir.join(name);
        match name {
            "bom.csv" => write_bom(&path, parts, limits)?,
            "cpl.csv" => write_cpl(&path, parts, limits)?,
            _ => unreachable!("all generated CSV names are handled"),
        }
        files.push(path);
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let artifacts = files
        .iter()
        .map(|path| descriptor_for_file(output_dir, path, limits))
        .collect::<Result<Vec<_>>>()?;
    let manifest = ManufacturingManifest {
        schema_version: 1,
        engine: "pcbex",
        engine_version: env!("CARGO_PKG_VERSION"),
        tools: kicad_identity.clone(),
        input: descriptor_for_bytes(input_name, input_bytes),
        project_inputs: project_input_descriptors,
        parts: ManufacturingCounts {
            total: parts.len(),
            bom: parts.iter().filter(|part| part.in_bom).count(),
            placement: parts.iter().filter(|part| part.in_pos).count(),
            dnp: parts.iter().filter(|part| part.dnp).count(),
        },
        artifacts,
        archive: ARCHIVE_NAME.to_string(),
    };
    let manifest_path = output_dir.join(MANIFEST_NAME);
    let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    manifest_bytes.push(b'\n');
    ensure_slice_with_limit(
        &manifest_bytes,
        limits.max_manifest_bytes,
        "manufacturing manifest",
    )?;
    write_bounded_file(
        &manifest_path,
        &manifest_bytes,
        limits,
        "manufacturing manifest",
    )?;

    files.push(manifest_path);
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let archive_path = output_dir.join(ARCHIVE_NAME);
    write_zip(&archive_path, &files, limits)?;
    scan_manufacturing_workspace(output_dir, limits, "manufacturing package stage")?;
    Ok(archive_path)
}

/// Remove KiCad wall-clock timestamps while retaining tool-version provenance.
pub fn normalize_kicad_artifacts(artifacts: &[PathBuf]) -> Result<()> {
    normalize_kicad_artifacts_with_limits(artifacts, ManufacturingLimits::production())
}

fn normalize_kicad_artifacts_with_limits(
    artifacts: &[PathBuf],
    limits: ManufacturingLimits,
) -> Result<()> {
    validate_regular_file_set(artifacts, limits, "KiCad normalization input")?;
    let mut normalized_total = 0_u64;
    for path in artifacts {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("KiCad artifact must be a regular file: {}", path.display());
        }
        ensure_file_size(metadata.len(), limits, "KiCad artifact", path)?;
        let source = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let opened = source
            .metadata()
            .with_context(|| format!("reading opened metadata for {}", path.display()))?;
        if !opened.is_file()
            || !same_file(&metadata, &opened)
            || opened.len() != metadata.len()
            || !opened_path_matches(&source, path)
                .with_context(|| format!("verifying opened artifact {}", path.display()))?
        {
            bail!("KiCad artifact changed while opening: {}", path.display());
        }
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("KiCad artifact is missing its parent directory"))?;
        let mut output = NamedTempFile::new_in(parent)
            .with_context(|| format!("creating normalized artifact beside {}", path.display()))?;
        let mut reader = BufReader::new(source);
        let mut replacements = 0_usize;
        let mut source_bytes = 0_u64;
        let mut output_bytes = 0_u64;
        let mut line = Vec::new();
        let line_limit = limits.max_file_bytes.min(MAX_NORMALIZATION_LINE_BYTES);
        loop {
            let read = read_bounded_line(&mut reader, &mut line, line_limit)
                .with_context(|| format!("reading bounded line from {}", path.display()))?;
            if read == 0 {
                break;
            }
            source_bytes = source_bytes
                .checked_add(read as u64)
                .ok_or_else(|| anyhow::anyhow!("KiCad normalization input byte count overflow"))?;
            while matches!(line.last(), Some(b'\r' | b'\n')) {
                line.pop();
            }
            let decoded = std::str::from_utf8(&line)
                .with_context(|| format!("decoding KiCad artifact {} as UTF-8", path.display()))?;
            let (normalized, replaced) = normalize_kicad_timestamp_line(decoded)?;
            replacements += usize::from(replaced);
            let next = u64::try_from(normalized.len())
                .ok()
                .and_then(|bytes| bytes.checked_add(1))
                .and_then(|bytes| output_bytes.checked_add(bytes))
                .ok_or_else(|| anyhow::anyhow!("KiCad normalization output byte count overflow"))?;
            if next > limits.max_file_bytes {
                bail!(
                    "KiCad normalized artifact exceeds the {}-byte file limit: {}",
                    limits.max_file_bytes,
                    path.display()
                );
            }
            output
                .write_all(normalized.as_bytes())
                .and_then(|()| output.write_all(b"\n"))
                .with_context(|| format!("normalizing {}", path.display()))?;
            output_bytes = next;
        }
        let after = reader
            .get_ref()
            .metadata()
            .with_context(|| format!("rechecking opened artifact {}", path.display()))?;
        if !same_file(&opened, &after)
            || after.len() != metadata.len()
            || source_bytes != metadata.len()
        {
            bail!(
                "KiCad artifact changed while being normalized: {}",
                path.display()
            );
        }
        let final_path = fs::symlink_metadata(path)
            .with_context(|| format!("rechecking artifact path {}", path.display()))?;
        if final_path.file_type().is_symlink()
            || !final_path.file_type().is_file()
            || !same_file(&metadata, &final_path)
            || final_path.len() != metadata.len()
            || !opened_path_matches(reader.get_ref(), path)
                .with_context(|| format!("rechecking opened artifact path {}", path.display()))?
        {
            bail!(
                "KiCad artifact path changed while being normalized: {}",
                path.display()
            );
        }
        drop(reader);
        if replacements == 0 {
            bail!(
                "KiCad artifact has no recognized creation timestamp to normalize: {}",
                path.display()
            );
        }
        output
            .flush()
            .with_context(|| format!("flushing normalized artifact {}", path.display()))?;
        output
            .as_file()
            .sync_all()
            .with_context(|| format!("syncing normalized artifact {}", path.display()))?;
        output
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("publishing normalized artifact {}", path.display()))?;
        normalized_total = normalized_total
            .checked_add(output_bytes)
            .ok_or_else(|| anyhow::anyhow!("normalized manufacturing byte count overflow"))?;
        if normalized_total > limits.max_total_bytes {
            bail!(
                "normalized manufacturing artifacts exceed the {}-byte aggregate limit",
                limits.max_total_bytes
            );
        }
    }
    Ok(())
}

fn normalize_kicad_timestamp_line(line: &str) -> Result<(String, bool)> {
    const ISO_TIMESTAMP: &str = "1970-01-01T00:00:00Z";
    const PLAIN_TIMESTAMP: &str = "1970-01-01 00:00:00";

    if let Some(marker) = line.find("TF.CreationDate,") {
        let value_start = marker + "TF.CreationDate,".len();
        let value_end = line[value_start..]
            .find('*')
            .map(|offset| value_start + offset)
            .unwrap_or(line.len());
        return Ok((
            format!(
                "{}{}{}",
                &line[..value_start],
                ISO_TIMESTAMP,
                &line[value_end..]
            ),
            true,
        ));
    }
    if (line.starts_with("G04 Created by ") || line.starts_with("; DRILL file "))
        && let Some(marker) = line.rfind(" date ")
    {
        let value_start = marker + " date ".len();
        let suffix = if line.starts_with("G04 ") { "*" } else { "" };
        return Ok((
            format!("{}{}{}", &line[..value_start], PLAIN_TIMESTAMP, suffix),
            true,
        ));
    }
    if line.starts_with("** Created on ") {
        return Ok((
            format!("** Created on {} **", ISO_TIMESTAMP.trim_end_matches('Z')),
            true,
        ));
    }
    let trimmed = line.trim_start();
    if trimmed.starts_with("\"CreationDate\":") {
        let indent = &line[..line.len() - trimmed.len()];
        let comma = if trimmed.ends_with(',') { "," } else { "" };
        return Ok((
            format!("{indent}\"CreationDate\": \"{ISO_TIMESTAMP}\"{comma}"),
            true,
        ));
    }
    Ok((line.to_string(), false))
}

/// Collect only regular files from a private, newly-created staging directory.
pub fn collect_staged_artifacts(staging_dir: &Path) -> Result<Vec<PathBuf>> {
    collect_staged_artifacts_with_limits(staging_dir, ManufacturingLimits::production())
}

fn collect_staged_artifacts_with_limits(
    staging_dir: &Path,
    limits: ManufacturingLimits,
) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut names = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in fs::read_dir(staging_dir)
        .with_context(|| format!("listing staging directory {}", staging_dir.display()))?
    {
        if files.len() >= limits.max_entries {
            bail!(
                "manufacturing staging directory contains more than {} entries",
                limits.max_entries
            );
        }
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            bail!(
                "manufacturing staging entry must be a regular file: {}",
                entry.path().display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("manufacturing artifact filename is not UTF-8"))?;
        validate_portable_name(&name, limits, "manufacturing artifact")?;
        if !names.insert(portable_manufacturing_name_key(&name)) {
            bail!("duplicate portable manufacturing artifact filename {name}");
        }
        if is_reserved_name(&name) {
            bail!("KiCad export produced reserved artifact name {name}");
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("reading metadata for {}", entry.path().display()))?;
        ensure_file_size(
            metadata.len(),
            limits,
            "manufacturing artifact",
            &entry.path(),
        )?;
        total_bytes = add_total_bytes(
            total_bytes,
            metadata.len(),
            limits,
            "manufacturing staging artifacts",
        )?;
        files.push(entry.path());
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
}

/// Fail closed when KiCad succeeds without writing every required layer/file class.
pub fn validate_exported_layer_set(
    artifacts: &[PathBuf],
    requested_layers: &[String],
) -> Result<()> {
    let names = artifacts
        .iter()
        .map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| anyhow::anyhow!("manufacturing artifact filename is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    for required in ["drc.rpt"] {
        if !names.contains(&required) {
            bail!("KiCad manufacturing export is missing {required}");
        }
    }
    if !names.iter().any(|name| name.ends_with(".drl")) {
        bail!("KiCad manufacturing export did not produce an Excellon drill file");
    }
    if !names.iter().any(|name| name.ends_with("-job.gbrjob")) {
        bail!("KiCad manufacturing export did not produce a Gerber job file");
    }
    for layer in requested_layers
        .iter()
        .filter(|layer| layer.ends_with(".Cu") || layer.as_str() == "Edge.Cuts")
    {
        let marker = format!("-{}.", layer.replace('.', "_"));
        if !names.iter().any(|name| name.contains(&marker)) {
            bail!("KiCad manufacturing export did not produce mandatory layer {layer}");
        }
    }
    Ok(())
}

/// Publish a complete private staging directory after preflighting the output names.
pub fn publish_staged_package(staging_dir: &Path, output_dir: &Path) -> Result<PathBuf> {
    publish_staged_package_with_limits(staging_dir, output_dir, ManufacturingLimits::production())
}

fn publish_staged_package_with_limits(
    staging_dir: &Path,
    output_dir: &Path,
    limits: ManufacturingLimits,
) -> Result<PathBuf> {
    scan_manufacturing_workspace(staging_dir, limits, "manufacturing publication stage")?;
    let output_dir = prepare_manufacturing_output_directory(output_dir)?;
    let output_dir = output_dir.as_path();
    let mut files = directory_regular_files(staging_dir, limits)?;
    files.sort_by(|left, right| {
        publish_rank(left)
            .cmp(&publish_rank(right))
            .then_with(|| left.file_name().cmp(&right.file_name()))
    });
    let archive_source = files
        .iter()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(ARCHIVE_NAME))
        .ok_or_else(|| {
            anyhow::anyhow!("staged manufacturing package did not contain {ARCHIVE_NAME}")
        })?;
    let archive_size = fs::symlink_metadata(archive_source)
        .with_context(|| format!("reading staged archive {}", archive_source.display()))?
        .len();
    if archive_size == 0 || archive_size > limits.max_archive_bytes {
        bail!(
            "staged manufacturing archive must contain 1 to {} bytes",
            limits.max_archive_bytes
        );
    }
    let staged_names = files
        .iter()
        .filter_map(|path| path.file_name())
        .collect::<BTreeSet<_>>();
    let staged_portable_names = files
        .iter()
        .filter_map(|path| path.file_name().and_then(|name| name.to_str()))
        .map(portable_manufacturing_name_key)
        .collect::<BTreeSet<_>>();
    let mut output_entries = 0_usize;
    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("listing manufacturing output {}", output_dir.display()))?
    {
        output_entries = output_entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("manufacturing output entry count overflow"))?;
        if output_entries > limits.max_entries {
            bail!(
                "manufacturing output contains more than {} entries",
                limits.max_entries
            );
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
        if staged_portable_names.contains(&portable_manufacturing_name_key(name_text))
            && !staged_names.contains(name.as_os_str())
        {
            bail!(
                "manufacturing output contains a non-portable name collision {}; use a dedicated output directory",
                entry.path().display()
            );
        }
        if !staged_names.contains(name.as_os_str()) && is_manufacturing_artifact_name(name_text) {
            bail!(
                "manufacturing output contains stale generated artifact {}; use a dedicated output directory",
                entry.path().display()
            );
        }
    }
    for source in &files {
        let name = source
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("staged artifact is missing its filename"))?;
        let destination = output_dir.join(name);
        match fs::symlink_metadata(&destination) {
            Ok(metadata)
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() =>
            {
                bail!(
                    "refusing to replace non-regular manufacturing destination {}",
                    destination.display()
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading metadata for {}", destination.display()));
            }
        }
    }
    let mut prepared = Vec::with_capacity(files.len());
    let mut copied_total = 0_u64;
    for source in files {
        let name = source
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("staged artifact is missing its filename"))?;
        let destination = output_dir.join(name);
        let mut temporary = NamedTempFile::new_in(output_dir)
            .with_context(|| format!("creating temporary file in {}", output_dir.display()))?;
        let copied = copy_regular_file_bounded(
            &source,
            temporary.as_file_mut(),
            limits,
            "staged manufacturing artifact",
        )?;
        copied_total = add_total_bytes(
            copied_total,
            copied,
            limits,
            "published manufacturing artifacts",
        )?;
        temporary
            .as_file()
            .sync_all()
            .with_context(|| format!("syncing staged artifact {}", source.display()))?;
        prepared.push((temporary, destination));
    }
    for (temporary, destination) in prepared {
        temporary
            .persist(&destination)
            .map_err(|error| error.error)
            .with_context(|| format!("publishing {}", destination.display()))?;
    }
    let archive = output_dir.join(ARCHIVE_NAME);
    let archive_metadata = fs::symlink_metadata(&archive).with_context(|| {
        format!(
            "reading published manufacturing archive {}",
            archive.display()
        )
    })?;
    if archive_metadata.file_type().is_symlink() || !archive_metadata.file_type().is_file() {
        bail!("staged manufacturing package did not contain {ARCHIVE_NAME}");
    }
    if archive_metadata.len() == 0 || archive_metadata.len() > limits.max_archive_bytes {
        bail!(
            "published manufacturing archive must contain 1 to {} bytes",
            limits.max_archive_bytes
        );
    }
    Ok(archive)
}

/// Validate and create the output before any external tool or private stage runs.
pub fn prepare_manufacturing_output_directory(output_dir: &Path) -> Result<PathBuf> {
    if output_dir
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        bail!("manufacturing output path must not contain parent-directory components");
    }
    reject_symlink_components(output_dir)?;
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    reject_symlink_components(output_dir)?;
    let output_metadata = fs::symlink_metadata(output_dir)
        .with_context(|| format!("reading metadata for {}", output_dir.display()))?;
    if output_metadata.file_type().is_symlink() || !output_metadata.file_type().is_dir() {
        bail!(
            "manufacturing output must be a real directory, not a symlink: {}",
            output_dir.display()
        );
    }
    let canonical = fs::canonicalize(output_dir)
        .with_context(|| format!("resolving manufacturing output {}", output_dir.display()))?;
    if canonical.parent().is_none() {
        bail!("manufacturing output must not be the filesystem root");
    }
    reject_symlink_components(&canonical)?;
    Ok(canonical)
}

fn write_bom(path: &Path, parts: &[ManufacturingPart], limits: ManufacturingLimits) -> Result<()> {
    let mut groups = BTreeMap::<(&str, &str, &str, &str, &str), Vec<&str>>::new();
    for part in parts.iter().filter(|part| part.in_bom) {
        groups
            .entry((
                part.value.as_str(),
                part.footprint.as_str(),
                part.mpn.as_deref().unwrap_or_default(),
                part.side.as_str(),
                if part.smd { "SMD" } else { "THT" },
            ))
            .or_default()
            .push(part.reference.as_str());
    }
    let mut output = String::from("Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n");
    ensure_slice_within_file_limit(output.as_bytes(), limits, "manufacturing BOM")?;
    for ((value, footprint, mpn, side, kind), mut references) in groups {
        references.sort();
        let designator_bytes = references
            .iter()
            .try_fold(0_usize, |total, reference| {
                total.checked_add(reference.len())
            })
            .ok_or_else(|| anyhow::anyhow!("manufacturing BOM designator byte count overflow"))?
            .checked_add(references.len().saturating_sub(1))
            .ok_or_else(|| anyhow::anyhow!("manufacturing BOM designator byte count overflow"))?;
        if u64::try_from(designator_bytes).unwrap_or(u64::MAX) > limits.max_file_bytes {
            bail!(
                "manufacturing BOM designators exceed the {}-byte file limit",
                limits.max_file_bytes
            );
        }
        let designators = references.join(",");
        let quantity = references.len().to_string();
        write_csv_row(
            &mut output,
            &[value, &designators, footprint, &quantity, mpn, side, kind],
            limits.max_file_bytes,
            "manufacturing BOM",
        )?;
    }
    write_bounded_file(path, output.as_bytes(), limits, "manufacturing BOM")?;
    Ok(())
}

fn write_cpl(path: &Path, parts: &[ManufacturingPart], limits: ManufacturingLimits) -> Result<()> {
    let mut output = String::from("Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n");
    ensure_slice_within_file_limit(output.as_bytes(), limits, "manufacturing CPL")?;
    let mut placed = parts.iter().filter(|part| part.in_pos).collect::<Vec<_>>();
    placed.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
    for part in placed {
        let x = format_mm(part.x_nm);
        let y = format_mm(part.y_nm);
        let rotation = format_mdeg(part.rotation_mdeg);
        write_csv_row(
            &mut output,
            &[&part.reference, &x, &y, &rotation, &part.side],
            limits.max_file_bytes,
            "manufacturing CPL",
        )?;
    }
    write_bounded_file(path, output.as_bytes(), limits, "manufacturing CPL")?;
    Ok(())
}

fn write_csv_row(output: &mut String, values: &[&str], max_bytes: u64, label: &str) -> Result<()> {
    let mut row_bytes = values.len().saturating_sub(1);
    for value in values {
        let escaped = value
            .bytes()
            .filter(|byte| *byte == b'"')
            .count()
            .checked_add(value.len())
            .ok_or_else(|| anyhow::anyhow!("{label} CSV row byte count overflow"))?;
        let escaped = if value
            .chars()
            .any(|character| matches!(character, ',' | '"' | '\r' | '\n'))
        {
            escaped
                .checked_add(2)
                .ok_or_else(|| anyhow::anyhow!("{label} CSV row byte count overflow"))?
        } else {
            value.len()
        };
        row_bytes = row_bytes
            .checked_add(escaped)
            .ok_or_else(|| anyhow::anyhow!("{label} CSV row byte count overflow"))?;
    }
    row_bytes = row_bytes
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("{label} CSV row byte count overflow"))?;
    let next = output
        .len()
        .checked_add(row_bytes)
        .ok_or_else(|| anyhow::anyhow!("{label} byte count overflow"))?;
    if u64::try_from(next).unwrap_or(u64::MAX) > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte file limit");
    }
    output.reserve(row_bytes);
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        if value
            .chars()
            .any(|character| matches!(character, ',' | '"' | '\r' | '\n'))
        {
            output.push('"');
            for character in value.chars() {
                if character == '"' {
                    output.push('"');
                }
                output.push(character);
            }
            output.push('"');
        } else {
            output.push_str(value);
        }
    }
    output.push('\n');
    Ok(())
}

fn format_mm(value_nm: i64) -> String {
    format_scaled_integer(value_nm, 1_000_000, 6, true)
}

fn format_mdeg(value_mdeg: i64) -> String {
    format_scaled_integer(value_mdeg, 1_000, 3, false)
}

fn format_scaled_integer(value: i64, scale: i128, precision: usize, fixed: bool) -> String {
    let value = i128::from(value);
    let sign = if value < 0 { "-" } else { "" };
    let magnitude = value.abs();
    let whole = magnitude / scale;
    let fraction = magnitude % scale;
    if !fixed && fraction == 0 {
        format!("{sign}{whole}")
    } else {
        format!("{sign}{whole}.{fraction:0precision$}")
    }
}

fn directory_regular_files(directory: &Path, limits: ManufacturingLimits) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut names = BTreeSet::new();
    let mut total_bytes = 0_u64;
    for entry in
        fs::read_dir(directory).with_context(|| format!("listing {}", directory.display()))?
    {
        if files.len() >= limits.max_entries {
            bail!(
                "manufacturing directory contains more than {} entries: {}",
                limits.max_entries,
                directory.display()
            );
        }
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            bail!(
                "manufacturing entry must be a regular file: {}",
                entry.path().display()
            );
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("manufacturing entry filename is not UTF-8"))?;
        validate_portable_name(&name, limits, "manufacturing entry")?;
        if !names.insert(portable_manufacturing_name_key(&name)) {
            bail!("duplicate portable manufacturing entry filename {name}");
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("reading metadata for {}", entry.path().display()))?;
        ensure_file_size(metadata.len(), limits, "manufacturing entry", &entry.path())?;
        total_bytes = add_total_bytes(
            total_bytes,
            metadata.len(),
            limits,
            "manufacturing directory",
        )?;
        files.push(entry.path());
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
}

fn validate_exported_artifacts(
    output_dir: &Path,
    artifacts: &[PathBuf],
    limits: ManufacturingLimits,
) -> Result<Vec<PathBuf>> {
    if artifacts.len() > limits.max_entries {
        bail!(
            "manufacturing export contains more than {} artifacts",
            limits.max_entries
        );
    }
    let mut names = BTreeSet::new();
    let mut validated = Vec::with_capacity(artifacts.len());
    let mut total_bytes = 0_u64;
    for path in artifacts {
        if path.parent() != Some(output_dir) {
            bail!(
                "manufacturing artifact must be a direct child of the staging directory: {}",
                path.display()
            );
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("manufacturing artifact filename is not UTF-8"))?;
        validate_portable_name(name, limits, "manufacturing artifact")?;
        if is_reserved_name(name) {
            bail!("exported artifact uses reserved filename {name}");
        }
        if !names.insert(portable_manufacturing_name_key(name)) {
            bail!("duplicate manufacturing artifact filename {name}");
        }
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!(
                "manufacturing artifact must be a regular file: {}",
                path.display()
            );
        }
        ensure_file_size(metadata.len(), limits, "manufacturing artifact", path)?;
        if name.ends_with("-job.gbrjob") {
            ensure_file_size_with_limit(
                metadata.len(),
                limits.max_manifest_bytes,
                "manufacturing Gerber job",
                path,
            )?;
        }
        total_bytes = add_total_bytes(
            total_bytes,
            metadata.len(),
            limits,
            "manufacturing exported artifacts",
        )?;
        validated.push(path.clone());
    }
    validated.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(validated)
}

fn is_reserved_name(name: &str) -> bool {
    name.eq_ignore_ascii_case(MANIFEST_NAME)
        || name.eq_ignore_ascii_case(ARCHIVE_NAME)
        || GENERATED_CSV_NAMES
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn is_manufacturing_artifact_name(name: &str) -> bool {
    if is_reserved_name(name) || name.eq_ignore_ascii_case("drc.rpt") {
        return true;
    }
    let Some(extension) = Path::new(name).extension().and_then(|value| value.to_str()) else {
        return false;
    };
    let extension = extension.to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "drl" | "gbr" | "gbrjob" | "gtl" | "gbl" | "gtp" | "gbp" | "gts" | "gbs" | "gto" | "gbo"
    ) || extension.strip_prefix('g').is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
    }) || extension.strip_prefix("gm").is_some_and(|suffix| {
        !suffix.is_empty() && suffix.chars().all(|value| value.is_ascii_digit())
    })
}

fn reject_symlink_components(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("resolving current directory for manufacturing output")?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!(
                    "manufacturing output path contains symlink component {}",
                    current.display()
                )
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading metadata for {}", current.display()));
            }
        }
    }
    Ok(())
}

fn publish_rank(path: &Path) -> u8 {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(MANIFEST_NAME) => 1,
        Some(ARCHIVE_NAME) => 2,
        _ => 0,
    }
}

fn descriptor_for_file(
    output_dir: &Path,
    path: &Path,
    limits: ManufacturingLimits,
) -> Result<ArtifactDescriptor> {
    let name = path
        .strip_prefix(output_dir)
        .ok()
        .and_then(|relative| relative.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("manufacturing artifact path is not portable"))?;
    validate_portable_name(name, limits, "manufacturing artifact")?;
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        bail!(
            "manufacturing artifact must be a regular file: {}",
            path.display()
        );
    }
    let mut source = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let metadata = source
        .metadata()
        .with_context(|| format!("reading metadata for {}", path.display()))?;
    if !metadata.is_file()
        || !same_file(&path_metadata, &metadata)
        || metadata.len() != path_metadata.len()
        || !opened_path_matches(&source, path)
            .with_context(|| format!("verifying opened artifact {}", path.display()))?
    {
        bail!(
            "manufacturing artifact changed while opening: {}",
            path.display()
        );
    }
    let bytes = metadata.len();
    ensure_file_size(bytes, limits, "manufacturing artifact", path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut hashed = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .with_context(|| format!("hashing {}", path.display()))?;
        if read == 0 {
            break;
        }
        hashed = hashed
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("manufacturing artifact hash byte count overflow"))?;
        if hashed > bytes || hashed > limits.max_file_bytes {
            bail!(
                "manufacturing artifact changed while hashing: {}",
                path.display()
            );
        }
        digest.update(&buffer[..read]);
    }
    let after = source
        .metadata()
        .with_context(|| format!("rechecking metadata for {}", path.display()))?;
    if !same_file(&metadata, &after) || hashed != bytes || after.len() != bytes {
        bail!(
            "manufacturing artifact changed while hashing: {}",
            path.display()
        );
    }
    let final_path = fs::symlink_metadata(path)
        .with_context(|| format!("rechecking artifact path {}", path.display()))?;
    if final_path.file_type().is_symlink()
        || !final_path.file_type().is_file()
        || !same_file(&path_metadata, &final_path)
        || final_path.len() != bytes
        || !opened_path_matches(&source, path)
            .with_context(|| format!("rechecking opened artifact path {}", path.display()))?
    {
        bail!(
            "manufacturing artifact path changed while hashing: {}",
            path.display()
        );
    }
    Ok(ArtifactDescriptor {
        path: name.to_string(),
        bytes,
        sha256: hex::encode(digest.finalize()),
    })
}

fn descriptor_for_bytes(path: &str, bytes: &[u8]) -> ArtifactDescriptor {
    ArtifactDescriptor {
        path: path.to_string(),
        bytes: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(bytes)),
    }
}

fn write_zip(path: &Path, files: &[PathBuf], limits: ManufacturingLimits) -> Result<()> {
    if files.is_empty() || files.len() > limits.max_entries {
        bail!(
            "manufacturing archive must contain 1 to {} files",
            limits.max_entries
        );
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("manufacturing archive is missing its parent directory"))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary archive beside {}", path.display()))?;
    let writer = BoundedSeekWriter::new(temporary.as_file_mut(), limits.max_archive_bytes);
    let mut zip = ZipWriter::new(writer);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6))
        .last_modified_time(zip::DateTime::default())
        .system(zip::System::Unix)
        .unix_permissions(0o644);
    let mut names = BTreeSet::new();
    let mut source_total = 0_u64;
    for file_path in files {
        let name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("manufacturing artifact has an invalid filename"))?;
        validate_portable_name(name, limits, "manufacturing archive entry")?;
        if !names.insert(portable_manufacturing_name_key(name)) {
            bail!("duplicate manufacturing archive entry {name}");
        }
        let source_metadata = fs::symlink_metadata(file_path)
            .with_context(|| format!("reading archive source metadata {}", file_path.display()))?;
        if source_metadata.file_type().is_symlink() || !source_metadata.file_type().is_file() {
            bail!(
                "manufacturing archive source must be a regular file: {}",
                file_path.display()
            );
        }
        let expected_bytes = source_metadata.len();
        ensure_file_size(
            expected_bytes,
            limits,
            "manufacturing archive source",
            file_path,
        )?;
        if name.to_ascii_lowercase().ends_with("-job.gbrjob") {
            ensure_file_size_with_limit(
                expected_bytes,
                limits.max_manifest_bytes,
                "manufacturing Gerber job",
                file_path,
            )?;
        }
        let mut copy_limits = limits;
        if name != MANIFEST_NAME {
            let expanded_remaining = limits
                .max_archive_uncompressed_bytes
                .saturating_sub(source_total);
            source_total = add_bytes_with_limit(
                source_total,
                expected_bytes,
                limits.max_archive_uncompressed_bytes,
                "manufacturing archive expanded artifacts",
            )?;
            copy_limits.max_file_bytes = copy_limits.max_file_bytes.min(expanded_remaining);
        } else {
            ensure_file_size_with_limit(
                expected_bytes,
                limits.max_manifest_bytes,
                "manufacturing manifest",
                file_path,
            )?;
        }
        zip.start_file(name, options)
            .with_context(|| format!("adding {name} to manufacturing archive"))?;
        let copied = copy_regular_file_bounded(
            file_path,
            &mut zip,
            copy_limits,
            "manufacturing archive source",
        )?;
        if copied != expected_bytes {
            bail!(
                "manufacturing archive source changed while copying: {}",
                file_path.display()
            );
        }
    }
    let writer = zip.finish().context("finalizing manufacturing archive")?;
    debug_assert!(source_total <= limits.max_archive_uncompressed_bytes);
    if writer.overflowed
        || writer.max_position == 0
        || writer.max_position > limits.max_archive_bytes
    {
        bail!(
            "manufacturing archive must contain 1 to {} bytes",
            limits.max_archive_bytes
        );
    }
    temporary
        .as_file_mut()
        .flush()
        .with_context(|| format!("flushing manufacturing archive {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("syncing manufacturing archive {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing manufacturing archive {}", path.display()))?;
    Ok(())
}

fn read_bounded_line<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
    max_bytes: u64,
) -> io::Result<usize> {
    line.clear();
    let read_limit = max_bytes
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "line limit overflow"))?;
    let mut bounded = Read::take(reader, read_limit);
    let read = bounded.read_until(b'\n', line)?;
    if u64::try_from(read).unwrap_or(u64::MAX) > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("line exceeds the {max_bytes}-byte limit"),
        ));
    }
    Ok(read)
}

fn validate_portable_name(name: &str, limits: ManufacturingLimits, label: &str) -> Result<()> {
    validate_manufacturing_basename(name, limits.max_name_bytes, label)
}

fn validate_kicad_identity(identity: &KiCadIdentity) -> Result<()> {
    if identity.version.trim().is_empty()
        || identity.version.trim() != identity.version
        || identity.version.chars().count() > 256
    {
        bail!("KiCad CLI version must contain 1 to 256 trimmed characters");
    }
    if identity.about_sha256.len() != 64
        || !identity
            .about_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("KiCad CLI about digest must be a lowercase SHA-256 value");
    }
    Ok(())
}

fn ensure_slice_within_file_limit(
    bytes: &[u8],
    limits: ManufacturingLimits,
    label: &str,
) -> Result<()> {
    ensure_slice_with_limit(bytes, limits.max_file_bytes, label)
}

fn ensure_slice_with_limit(bytes: &[u8], max_bytes: u64, label: &str) -> Result<()> {
    let bytes = u64::try_from(bytes.len())
        .map_err(|_| anyhow::anyhow!("{label} byte count cannot be represented"))?;
    if bytes == 0 || bytes > max_bytes {
        bail!("{label} must contain 1 to {max_bytes} bytes");
    }
    Ok(())
}

fn ensure_file_size(
    bytes: u64,
    limits: ManufacturingLimits,
    label: &str,
    path: &Path,
) -> Result<()> {
    ensure_file_size_with_limit(bytes, limits.max_file_bytes, label, path)
}

fn ensure_file_size_with_limit(bytes: u64, max_bytes: u64, label: &str, path: &Path) -> Result<()> {
    if bytes == 0 || bytes > max_bytes {
        bail!(
            "{label} must contain 1 to {} bytes: {}",
            max_bytes,
            path.display()
        );
    }
    Ok(())
}

fn add_total_bytes(
    current: u64,
    additional: u64,
    limits: ManufacturingLimits,
    label: &str,
) -> Result<u64> {
    add_bytes_with_limit(current, additional, limits.max_total_bytes, label)
}

fn add_bytes_with_limit(current: u64, additional: u64, max_bytes: u64, label: &str) -> Result<u64> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| anyhow::anyhow!("{label} byte count overflow"))?;
    if total > max_bytes {
        bail!("{label} exceeds the {max_bytes}-byte aggregate limit");
    }
    Ok(total)
}

fn write_bounded_file(
    path: &Path,
    contents: &[u8],
    limits: ManufacturingLimits,
    label: &str,
) -> Result<()> {
    ensure_slice_within_file_limit(contents, limits, label)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} path is missing its parent directory"))?;
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("creating temporary {label} beside {}", path.display()))?;
    temporary
        .write_all(contents)
        .with_context(|| format!("writing bounded {label} {}", path.display()))?;
    temporary
        .flush()
        .with_context(|| format!("flushing {label} {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("syncing {label} {}", path.display()))?;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("publishing {label} {}", path.display()))?;
    Ok(())
}

fn validate_regular_file_set(
    files: &[PathBuf],
    limits: ManufacturingLimits,
    label: &str,
) -> Result<u64> {
    if files.len() > limits.max_entries {
        bail!("{label} contains more than {} files", limits.max_entries);
    }
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for path in files {
        if !seen.insert(path.clone()) {
            bail!("{label} contains duplicate path {}", path.display());
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("{label} filename is not UTF-8"))?;
        validate_portable_name(name, limits, label)?;
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading {label} metadata {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            bail!("{label} must be a regular file: {}", path.display());
        }
        ensure_file_size(metadata.len(), limits, label, path)?;
        total = add_total_bytes(total, metadata.len(), limits, label)?;
    }
    Ok(total)
}

fn copy_regular_file_bounded<W: Write>(
    path: &Path,
    output: &mut W,
    limits: ManufacturingLimits,
    label: &str,
) -> Result<u64> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("reading {label} metadata {}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_file() {
        bail!("{label} must be a regular file: {}", path.display());
    }
    ensure_file_size(path_metadata.len(), limits, label, path)?;
    let mut input =
        File::open(path).with_context(|| format!("opening {label} {}", path.display()))?;
    let opened = input
        .metadata()
        .with_context(|| format!("reading opened {label} metadata {}", path.display()))?;
    if !opened.is_file()
        || !same_file(&path_metadata, &opened)
        || opened.len() != path_metadata.len()
        || !opened_path_matches(&input, path)
            .with_context(|| format!("verifying opened {label} {}", path.display()))?
    {
        bail!("{label} changed while opening: {}", path.display());
    }

    let expected = opened.len();
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .with_context(|| format!("reading {label} {}", path.display()))?;
        if read == 0 {
            break;
        }
        let next = copied
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("{label} byte count overflow"))?;
        if next > expected || next > limits.max_file_bytes {
            bail!("{label} changed while reading: {}", path.display());
        }
        output
            .write_all(&buffer[..read])
            .with_context(|| format!("copying {label} {}", path.display()))?;
        copied = next;
    }
    let after = input
        .metadata()
        .with_context(|| format!("rechecking {label} metadata {}", path.display()))?;
    if !same_file(&opened, &after) || copied != expected || after.len() != expected {
        bail!("{label} changed while reading: {}", path.display());
    }
    let final_path = fs::symlink_metadata(path)
        .with_context(|| format!("rechecking {label} path {}", path.display()))?;
    if final_path.file_type().is_symlink()
        || !final_path.file_type().is_file()
        || !same_file(&path_metadata, &final_path)
        || final_path.len() != expected
        || !opened_path_matches(&input, path)
            .with_context(|| format!("rechecking opened {label} path {}", path.display()))?
    {
        bail!("{label} path changed while reading: {}", path.display());
    }
    Ok(copied)
}

struct BoundedSeekWriter<W> {
    inner: W,
    limit: u64,
    position: u64,
    max_position: u64,
    overflowed: bool,
}

impl<W> BoundedSeekWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            limit,
            position: 0,
            max_position: 0,
            overflowed: false,
        }
    }
}

impl<W: Write> Write for BoundedSeekWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let requested = u64::try_from(buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "archive write size cannot be represented",
            )
        })?;
        let end = self.position.checked_add(requested).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "archive byte count overflow")
        })?;
        let allowed = self.limit.saturating_sub(self.position).min(requested);
        if allowed > 0 {
            let allowed = usize::try_from(allowed).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "bounded archive write cannot be represented",
                )
            })?;
            self.inner.write_all(&buffer[..allowed])?;
        }
        self.overflowed |= end > self.limit;
        self.position = end;
        self.max_position = self.max_position.max(self.position);
        // Report the virtual write as complete. ZipWriter can then finalize
        // cleanly while the private file never grows beyond the quota.
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<W: Seek> Seek for BoundedSeekWriter<W> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(target) => Some(target),
            SeekFrom::Current(offset) => self.position.checked_add_signed(offset),
            SeekFrom::End(offset) => self.max_position.checked_add_signed(offset),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "archive seek overflow"))?;
        if target <= self.limit {
            self.inner.seek(SeekFrom::Start(target))?;
        } else {
            self.overflowed = true;
        }
        self.position = target;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use zip::ZipArchive;

    fn part(
        reference: &str,
        value: &str,
        smd: bool,
        in_bom: bool,
        in_pos: bool,
    ) -> ManufacturingPart {
        ManufacturingPart {
            reference: reference.to_string(),
            value: value.to_string(),
            footprint: "Test:Footprint".to_string(),
            x_nm: 1_250_000,
            y_nm: 2_500_000,
            rotation_mdeg: 90_000,
            side: "F".to_string(),
            mpn: Some("C123".to_string()),
            in_bom,
            dnp: !in_bom,
            in_pos,
            smd,
        }
    }

    fn identity() -> KiCadIdentity {
        KiCadIdentity {
            version: "10.0.5".to_string(),
            about_sha256: "a".repeat(64),
        }
    }

    #[test]
    fn writes_grouped_bom_and_only_explicit_artifacts() {
        let staging = tempdir().unwrap();
        let path = staging.path();
        fs::write(path.join("drc.rpt"), "DRC clean\n").unwrap();
        fs::write(path.join("board-F_Cu.gtl"), "G04 copper*\n").unwrap();
        fs::write(path.join("not-exported.secret"), "do not package").unwrap();
        let parts = vec![
            part("R2", "10k", true, true, true),
            part("R1", "10k", true, true, true),
            part("H1", "Mount", false, false, false),
        ];
        let archive = write_manufacturing_package(
            path,
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &parts,
            &[path.join("drc.rpt"), path.join("board-F_Cu.gtl")],
            &identity(),
        )
        .unwrap();
        let bom = fs::read_to_string(path.join("bom.csv")).unwrap();
        assert!(bom.contains("R1,R2"));
        let cpl = fs::read_to_string(path.join("cpl.csv")).unwrap();
        assert!(cpl.contains("R1,1.250000,2.500000,90,F"));
        assert!(cpl.find("R1,").unwrap() < cpl.find("R2,").unwrap());
        assert!(archive.is_file());
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(path.join(MANIFEST_NAME)).unwrap()).unwrap();
        assert_eq!(manifest["input"]["path"], "board.kicad_pcb");
        let artifact_names = manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|artifact| artifact["path"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(artifact_names.contains(&"board-F_Cu.gtl"));
        assert!(artifact_names.contains(&"drc.rpt"));
        assert!(!artifact_names.contains(&"not-exported.secret"));

        let mut zip = ZipArchive::new(File::open(archive).unwrap()).unwrap();
        assert!(zip.by_name("manifest.json").is_ok());
        assert!(zip.by_name("not-exported.secret").is_err());
    }

    #[test]
    fn archive_is_reproducible_across_input_and_staging_directories() {
        fn generate(staging: &Path, input: &Path) -> Vec<u8> {
            fs::write(staging.join("drc.rpt"), "DRC clean\n").unwrap();
            fs::write(staging.join("board-F_Cu.gtl"), "G04 copper*\n").unwrap();
            let archive = write_manufacturing_package(
                staging,
                input,
                b"same board bytes",
                &[],
                &[part("R1", "10k", true, true, true)],
                &[staging.join("board-F_Cu.gtl"), staging.join("drc.rpt")],
                &identity(),
            )
            .unwrap();
            fs::read(archive).unwrap()
        }

        let left = tempdir().unwrap();
        let right = tempdir().unwrap();
        let left_bytes = generate(left.path(), Path::new("/workspace/a/board.kicad_pcb"));
        let right_bytes = generate(right.path(), Path::new("/different/b/board.kicad_pcb"));
        assert_eq!(left_bytes, right_bytes);
    }

    #[test]
    fn normalizes_all_kicad_creation_timestamp_formats() {
        let staging = tempdir().unwrap();
        let gerber = staging.path().join("board-F_Cu.gtl");
        let drill = staging.path().join("board.drl");
        let job = staging.path().join("board-job.gbrjob");
        let drc = staging.path().join("drc.rpt");
        fs::write(
            &gerber,
            "%TF.CreationDate,2026-08-02T19:11:08+09:00*%\nG04 Created by KiCad date 2026-08-02 19:11:08*\n",
        )
        .unwrap();
        fs::write(
            &drill,
            "; DRILL file KiCad date 2026-08-02T19:11:09\n; #@! TF.CreationDate,2026-08-02T19:11:09+09:00\n",
        )
        .unwrap();
        fs::write(
            &job,
            "{\n  \"CreationDate\": \"2026-08-02T19:11:08+09:00\",\n  \"FilesAttributes\": []\n}\n",
        )
        .unwrap();
        fs::write(&drc, "** Created on 2026-08-02T19:18:04 **\n").unwrap();

        normalize_kicad_artifacts(&[gerber.clone(), drill.clone(), job.clone(), drc.clone()])
            .unwrap();
        for path in [gerber, drill, job, drc] {
            let normalized = fs::read_to_string(path).unwrap();
            assert!(!normalized.contains("2026-08-02"));
            assert!(normalized.contains("1970-01-01"));
        }
    }

    #[test]
    fn validates_mandatory_inner_copper_drill_and_job_outputs() {
        let layers = ["F.Cu", "In1.Cu", "B.Cu", "Edge.Cuts"]
            .map(str::to_string)
            .to_vec();
        let complete = [
            "drc.rpt",
            "board.drl",
            "board-job.gbrjob",
            "board-F_Cu.gtl",
            "board-In1_Cu.g1",
            "board-B_Cu.gbl",
            "board-Edge_Cuts.gm1",
        ]
        .map(PathBuf::from)
        .to_vec();
        validate_exported_layer_set(&complete, &layers).unwrap();

        let incomplete = complete
            .into_iter()
            .filter(|path| path.to_string_lossy() != "board-In1_Cu.g1")
            .collect::<Vec<_>>();
        assert!(
            validate_exported_layer_set(&incomplete, &layers)
                .unwrap_err()
                .to_string()
                .contains("In1.Cu")
        );
    }

    #[test]
    fn formats_signed_coordinates_without_float_precision_loss() {
        assert_eq!(format_mm(i64::MIN), "-9223372036854.775808");
        assert_eq!(format_mm(i64::MAX), "9223372036854.775807");
        assert_eq!(format_mdeg(-90_050), "-90.050");
        assert_eq!(format_mdeg(90_000), "90");
    }

    #[test]
    fn publishing_does_not_package_or_overwrite_unrelated_output_files() {
        let staging = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(staging.path().join("drc.rpt"), "DRC clean\n").unwrap();
        fs::write(staging.path().join("board-F_Cu.gtl"), "G04 copper*\n").unwrap();
        let exported = collect_staged_artifacts(staging.path()).unwrap();
        write_manufacturing_package(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &[part("R1", "10k", true, true, true)],
            &exported,
            &identity(),
        )
        .unwrap();
        fs::write(output.path().join("unrelated.secret"), "keep me").unwrap();

        let archive = publish_staged_package(staging.path(), output.path()).unwrap();
        assert_eq!(
            fs::read_to_string(output.path().join("unrelated.secret")).unwrap(),
            "keep me"
        );
        let mut zip = ZipArchive::new(File::open(archive).unwrap()).unwrap();
        assert!(zip.by_name("unrelated.secret").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn publishing_ignores_unrelated_non_utf8_output_names() {
        use std::os::unix::ffi::OsStringExt;

        let staging = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(staging.path().join("drc.rpt"), "new DRC\n").unwrap();
        fs::write(staging.path().join("manufacturing.zip"), "new archive").unwrap();
        let unrelated = std::ffi::OsString::from_vec(b"unrelated-\xff".to_vec());
        fs::write(output.path().join(&unrelated), "keep me").unwrap();

        publish_staged_package(staging.path(), output.path()).unwrap();
        assert_eq!(
            fs::read_to_string(output.path().join(unrelated)).unwrap(),
            "keep me"
        );
    }

    #[test]
    fn publishing_rejects_stale_manufacturing_artifacts_before_writing() {
        let staging = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(staging.path().join("drc.rpt"), "new DRC\n").unwrap();
        fs::write(staging.path().join("manufacturing.zip"), "new archive").unwrap();
        fs::write(output.path().join("drc.rpt"), "old DRC\n").unwrap();
        fs::write(output.path().join("old-In2_Cu.g2"), "stale copper\n").unwrap();

        let error = publish_staged_package(staging.path(), output.path()).unwrap_err();
        assert!(error.to_string().contains("stale generated artifact"));
        assert_eq!(
            fs::read_to_string(output.path().join("drc.rpt")).unwrap(),
            "old DRC\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn publishing_rejects_symlink_paths_and_preflights_all_destinations() {
        use std::os::unix::fs::symlink;

        let staging = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(staging.path().join("drc.rpt"), "new DRC\n").unwrap();
        fs::write(staging.path().join("manufacturing.zip"), "new archive").unwrap();
        fs::write(output.path().join("drc.rpt"), "old DRC\n").unwrap();
        symlink(
            output.path().join("archive-target"),
            output.path().join("manufacturing.zip"),
        )
        .unwrap();

        let error = publish_staged_package(staging.path(), output.path()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("non-regular manufacturing destination")
        );
        assert_eq!(
            fs::read_to_string(output.path().join("drc.rpt")).unwrap(),
            "old DRC\n"
        );

        let parent = tempdir().unwrap();
        let target = tempdir().unwrap();
        let linked_output = parent.path().join("linked-output");
        symlink(target.path(), &linked_output).unwrap();
        let error = publish_staged_package(staging.path(), &linked_output).unwrap_err();
        assert!(error.to_string().contains("symlink component"));
        assert!(fs::read_dir(target.path()).unwrap().next().is_none());
    }

    #[test]
    fn output_preflight_rejects_parent_directory_components_without_side_effects() {
        let parent = tempdir().unwrap();
        let missing = parent.path().join("missing");
        let output = missing.join("..");

        let error = prepare_manufacturing_output_directory(&output).unwrap_err();
        assert!(error.to_string().contains("parent-directory components"));
        assert!(!missing.exists());
    }

    #[test]
    fn rejects_missing_drc_and_non_direct_artifacts() {
        let staging = tempdir().unwrap();
        fs::create_dir(staging.path().join("nested")).unwrap();
        let nested = staging.path().join("nested/board.gbr");
        fs::write(&nested, "gerber").unwrap();
        let error = write_manufacturing_package(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &[],
            &[nested],
            &identity(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("direct child"));

        fs::write(staging.path().join("board.gbr"), "gerber").unwrap();
        let error = write_manufacturing_package(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &[],
            &[staging.path().join("board.gbr")],
            &identity(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("drc.rpt"));
    }

    fn small_limits() -> ManufacturingLimits {
        ManufacturingLimits {
            max_entries: 8,
            max_depth: 4,
            max_file_bytes: 64,
            max_total_bytes: 128,
            max_archive_bytes: 64,
            max_archive_uncompressed_bytes: 128,
            max_manifest_bytes: 64,
            max_name_bytes: 32,
        }
    }

    #[test]
    fn staged_collection_enforces_exact_and_plus_one_quotas() {
        let staging = tempdir().unwrap();
        fs::write(staging.path().join("a.gbr"), b"12").unwrap();
        fs::write(staging.path().join("b.drl"), b"3").unwrap();

        let mut exact = small_limits();
        exact.max_entries = 2;
        exact.max_file_bytes = 2;
        exact.max_total_bytes = 3;
        let files = collect_staged_artifacts_with_limits(staging.path(), exact).unwrap();
        assert_eq!(files.len(), 2);

        let mut count_over = exact;
        count_over.max_entries = 1;
        let error = collect_staged_artifacts_with_limits(staging.path(), count_over).unwrap_err();
        assert!(
            error.to_string().contains("more than 1 entries"),
            "{error:#}"
        );

        let mut file_over = exact;
        file_over.max_file_bytes = 1;
        let error = collect_staged_artifacts_with_limits(staging.path(), file_over).unwrap_err();
        assert!(error.to_string().contains("1 to 1 bytes"), "{error:#}");

        let mut total_over = exact;
        total_over.max_total_bytes = 2;
        let error = collect_staged_artifacts_with_limits(staging.path(), total_over).unwrap_err();
        assert!(error.to_string().contains("aggregate limit"), "{error:#}");
    }

    #[test]
    fn normalization_rejects_giant_lines_without_replacing_the_source() {
        let staging = tempdir().unwrap();
        let artifact = staging.path().join("board-F_Cu.gtl");
        let mut original = b"G04 Created by KiCad date 2026-08-02 ".to_vec();
        original.extend(std::iter::repeat_n(
            b'x',
            usize::try_from(MAX_NORMALIZATION_LINE_BYTES).unwrap(),
        ));
        fs::write(&artifact, &original).unwrap();

        let mut limits = ManufacturingLimits::production();
        limits.max_file_bytes = MAX_NORMALIZATION_LINE_BYTES * 2;
        limits.max_total_bytes = MAX_NORMALIZATION_LINE_BYTES * 2;
        let error = normalize_kicad_artifacts_with_limits(std::slice::from_ref(&artifact), limits)
            .unwrap_err();
        assert!(format!("{error:#}").contains("line exceeds"), "{error:#}");
        assert_eq!(fs::read(&artifact).unwrap(), original);
    }

    #[test]
    fn normalization_output_overflow_preserves_the_source() {
        let staging = tempdir().unwrap();
        let artifact = staging.path().join("drc.rpt");
        let original = b"** Created on x **";
        fs::write(&artifact, original).unwrap();
        let mut limits = small_limits();
        limits.max_file_bytes = original.len() as u64;

        let error = normalize_kicad_artifacts_with_limits(std::slice::from_ref(&artifact), limits)
            .unwrap_err();
        assert!(
            error.to_string().contains("normalized artifact exceeds"),
            "{error:#}"
        );
        assert_eq!(fs::read(&artifact).unwrap(), original);
    }

    #[test]
    fn archive_limit_is_inclusive_and_failure_preserves_existing_output() {
        let staging = tempdir().unwrap();
        let source = staging.path().join("drc.rpt");
        fs::write(&source, b"DRC clean\n").unwrap();

        let probe = staging.path().join("probe.zip");
        let mut probe_limits = small_limits();
        probe_limits.max_archive_bytes = 4096;
        write_zip(&probe, std::slice::from_ref(&source), probe_limits).unwrap();
        let exact_bytes = fs::metadata(&probe).unwrap().len();

        let exact = staging.path().join("exact.zip");
        let mut exact_limits = probe_limits;
        exact_limits.max_archive_bytes = exact_bytes;
        write_zip(&exact, std::slice::from_ref(&source), exact_limits).unwrap();
        assert_eq!(fs::metadata(&exact).unwrap().len(), exact_bytes);

        let destination = staging.path().join("manufacturing.zip");
        fs::write(&destination, b"known-good").unwrap();
        let mut one_over = exact_limits;
        one_over.max_archive_bytes = exact_bytes - 1;
        let error = write_zip(&destination, &[source], one_over).unwrap_err();
        assert!(error.to_string().contains("archive"), "{error:#}");
        assert_eq!(fs::read(destination).unwrap(), b"known-good");
    }

    #[test]
    fn expanded_archive_limit_is_inclusive_and_failure_preserves_existing_output() {
        let staging = tempdir().unwrap();
        let first = staging.path().join("first.gbr");
        let second = staging.path().join("second.drl");
        fs::write(&first, b"12").unwrap();
        fs::write(&second, b"3").unwrap();

        let destination = staging.path().join("expanded.zip");
        let mut exact = small_limits();
        exact.max_archive_bytes = 4096;
        exact.max_archive_uncompressed_bytes = 3;
        write_zip(&destination, &[first.clone(), second.clone()], exact).unwrap();
        let known_good = fs::read(&destination).unwrap();

        let mut one_over = exact;
        one_over.max_archive_uncompressed_bytes = 2;
        let error = write_zip(&destination, &[first, second], one_over).unwrap_err();
        assert!(format!("{error:#}").contains("expanded"), "{error:#}");
        assert_eq!(fs::read(destination).unwrap(), known_good);
    }

    #[test]
    fn manifest_limit_is_inclusive_and_failure_preserves_existing_manifest() {
        let staging = tempdir().unwrap();
        let drc = staging.path().join("drc.rpt");
        let copper = staging.path().join("board-F_Cu.gtl");
        fs::write(&drc, b"DRC clean\n").unwrap();
        fs::write(&copper, b"G04 copper*\n").unwrap();
        let artifacts = vec![drc, copper];

        write_manufacturing_package(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &[part("R1", "10k", true, true, true)],
            &artifacts,
            &identity(),
        )
        .unwrap();
        let known_good = fs::read(staging.path().join(MANIFEST_NAME)).unwrap();

        let mut exact = ManufacturingLimits::production();
        exact.max_manifest_bytes = known_good.len() as u64;
        write_manufacturing_package_with_limits(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &[part("R1", "10k", true, true, true)],
            &artifacts,
            &identity(),
            exact,
        )
        .unwrap();

        let mut one_over = exact;
        one_over.max_manifest_bytes -= 1;
        let error = write_manufacturing_package_with_limits(
            staging.path(),
            Path::new("board.kicad_pcb"),
            b"board",
            &[],
            &[part("R1", "10k", true, true, true)],
            &artifacts,
            &identity(),
            one_over,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("manifest"), "{error:#}");
        assert_eq!(
            fs::read(staging.path().join(MANIFEST_NAME)).unwrap(),
            known_good
        );
    }

    #[test]
    fn publication_quota_failure_leaves_existing_outputs_unchanged() {
        let staging = tempdir().unwrap();
        let output = tempdir().unwrap();
        fs::write(staging.path().join("drc.rpt"), b"new DRC").unwrap();
        fs::write(staging.path().join(ARCHIVE_NAME), b"oversized archive").unwrap();
        fs::write(output.path().join("drc.rpt"), b"known-good DRC").unwrap();
        let mut limits = small_limits();
        limits.max_archive_bytes = 4;

        let error =
            publish_staged_package_with_limits(staging.path(), output.path(), limits).unwrap_err();
        assert!(error.to_string().contains("archive"), "{error:#}");
        assert_eq!(
            fs::read(output.path().join("drc.rpt")).unwrap(),
            b"known-good DRC"
        );
        assert!(!output.path().join(ARCHIVE_NAME).exists());
    }

    #[test]
    fn copy_rejects_a_source_that_grows_during_streaming() {
        struct GrowingWriter {
            source: PathBuf,
            bytes: Vec<u8>,
            grew: bool,
        }

        impl Write for GrowingWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(buffer);
                if !self.grew {
                    let mut source = fs::OpenOptions::new().append(true).open(&self.source)?;
                    source.write_all(b"growth")?;
                    self.grew = true;
                }
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let staging = tempdir().unwrap();
        let source = staging.path().join("large.gbr");
        fs::write(&source, vec![b'x'; 96 * 1024]).unwrap();
        let mut limits = ManufacturingLimits::production();
        limits.max_file_bytes = 128 * 1024;
        let mut writer = GrowingWriter {
            source: source.clone(),
            bytes: Vec::new(),
            grew: false,
        };
        let error =
            copy_regular_file_bounded(&source, &mut writer, limits, "test source").unwrap_err();
        assert!(
            error.to_string().contains("changed while reading"),
            "{error:#}"
        );
        assert!(writer.bytes.len() <= 96 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn copy_rejects_a_same_size_source_replacement_during_streaming() {
        struct ReplacingWriter {
            source: PathBuf,
            replacement: PathBuf,
            bytes: Vec<u8>,
            replaced: bool,
        }

        impl Write for ReplacingWriter {
            fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
                self.bytes.extend_from_slice(buffer);
                if !self.replaced {
                    fs::rename(&self.replacement, &self.source)?;
                    self.replaced = true;
                }
                Ok(buffer.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let staging = tempdir().unwrap();
        let source = staging.path().join("source.gbr");
        let replacement = staging.path().join("replacement.gbr");
        fs::write(&source, vec![b'a'; 96 * 1024]).unwrap();
        fs::write(&replacement, vec![b'b'; 96 * 1024]).unwrap();
        let mut limits = ManufacturingLimits::production();
        limits.max_file_bytes = 128 * 1024;
        let mut writer = ReplacingWriter {
            source: source.clone(),
            replacement,
            bytes: Vec::new(),
            replaced: false,
        };
        let error =
            copy_regular_file_bounded(&source, &mut writer, limits, "test source").unwrap_err();
        assert!(format!("{error:#}").contains("path changed"), "{error:#}");
        assert!(writer.replaced);
    }

    #[test]
    fn staged_collection_rejects_nonportable_names() {
        let staging = tempdir().unwrap();
        fs::write(staging.path().join("bad:name.gbr"), b"1").unwrap();
        let error =
            collect_staged_artifacts_with_limits(staging.path(), small_limits()).unwrap_err();
        assert!(error.to_string().contains("non-portable"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn staged_collection_rejects_case_insensitive_name_collisions() {
        let staging = tempdir().unwrap();
        fs::write(staging.path().join("Layer.gbr"), b"1").unwrap();
        fs::write(staging.path().join("layer.gbr"), b"2").unwrap();
        let error =
            collect_staged_artifacts_with_limits(staging.path(), small_limits()).unwrap_err();
        assert!(
            error.to_string().contains("duplicate portable"),
            "{error:#}"
        );
    }
}
