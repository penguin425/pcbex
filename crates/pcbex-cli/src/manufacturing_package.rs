//! Factory-ready BOM, pick-and-place, manifest, and archive generation.

use anyhow::{Context, Result, bail};
use pcbex_kicad::ManufacturingPart;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const MANIFEST_NAME: &str = "manifest.json";
const ARCHIVE_NAME: &str = "manufacturing.zip";
const GENERATED_CSV_NAMES: [&str; 2] = ["bom.csv", "cpl.csv"];

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
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    let input_name = input_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("manufacturing input must have a UTF-8 filename"))?;
    let mut files = validate_exported_artifacts(output_dir, exported_artifacts)?;
    if !files
        .iter()
        .any(|path| path.file_name().and_then(|name| name.to_str()) == Some("drc.rpt"))
    {
        bail!("manufacturing package requires the generated drc.rpt artifact");
    }
    let mut input_names = BTreeSet::from([input_name.to_string()]);
    let mut project_input_descriptors = Vec::with_capacity(project_inputs.len());
    for project_input in project_inputs {
        let name = project_input
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .ok_or_else(|| anyhow::anyhow!("KiCad project input must have a UTF-8 filename"))?;
        if !input_names.insert(name.to_string()) {
            bail!("duplicate KiCad manufacturing input filename {name}");
        }
        project_input_descriptors.push(descriptor_for_bytes(name, &project_input.bytes));
    }
    project_input_descriptors.sort_by(|left, right| left.path.cmp(&right.path));

    for name in GENERATED_CSV_NAMES {
        let path = output_dir.join(name);
        match name {
            "bom.csv" => write_bom(&path, parts)?,
            "cpl.csv" => write_cpl(&path, parts)?,
            _ => unreachable!("all generated CSV names are handled"),
        }
        files.push(path);
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let artifacts = files
        .iter()
        .map(|path| descriptor_for_file(output_dir, path))
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
    fs::write(&manifest_path, &manifest_bytes)
        .with_context(|| format!("writing {}", manifest_path.display()))?;

    files.push(manifest_path);
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    let archive_path = output_dir.join(ARCHIVE_NAME);
    write_zip(&archive_path, &files)?;
    Ok(archive_path)
}

/// Remove KiCad wall-clock timestamps while retaining tool-version provenance.
pub fn normalize_kicad_artifacts(artifacts: &[PathBuf]) -> Result<()> {
    for path in artifacts {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("reading metadata for {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("KiCad artifact must be a regular file: {}", path.display());
        }
        let source = File::open(path).with_context(|| format!("opening {}", path.display()))?;
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("KiCad artifact is missing its parent directory"))?;
        let mut output = NamedTempFile::new_in(parent)
            .with_context(|| format!("creating normalized artifact beside {}", path.display()))?;
        let mut reader = BufReader::new(source);
        let mut replacements = 0_usize;
        let mut line = String::new();
        loop {
            line.clear();
            let read = reader
                .read_line(&mut line)
                .with_context(|| format!("decoding KiCad artifact {} as UTF-8", path.display()))?;
            if read == 0 {
                break;
            }
            while matches!(line.as_bytes().last(), Some(b'\r' | b'\n')) {
                line.pop();
            }
            let (normalized, replaced) = normalize_kicad_timestamp_line(&line)?;
            replacements += usize::from(replaced);
            writeln!(output, "{normalized}")
                .with_context(|| format!("normalizing {}", path.display()))?;
        }
        drop(reader);
        if replacements == 0 {
            bail!(
                "KiCad artifact has no recognized creation timestamp to normalize: {}",
                path.display()
            );
        }
        output
            .as_file()
            .sync_all()
            .with_context(|| format!("syncing normalized artifact {}", path.display()))?;
        output
            .persist(path)
            .map_err(|error| error.error)
            .with_context(|| format!("publishing normalized artifact {}", path.display()))?;
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
    let mut files = Vec::new();
    for entry in fs::read_dir(staging_dir)
        .with_context(|| format!("listing staging directory {}", staging_dir.display()))?
    {
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
        if is_reserved_name(&name) {
            bail!("KiCad export produced reserved artifact name {name}");
        }
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
    let output_dir = prepare_manufacturing_output_directory(output_dir)?;
    let output_dir = output_dir.as_path();
    let mut files = directory_regular_files(staging_dir)?;
    files.sort_by(|left, right| {
        publish_rank(left)
            .cmp(&publish_rank(right))
            .then_with(|| left.file_name().cmp(&right.file_name()))
    });
    let staged_names = files
        .iter()
        .filter_map(|path| path.file_name())
        .collect::<BTreeSet<_>>();
    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("listing manufacturing output {}", output_dir.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name_text) = name.to_str() else {
            continue;
        };
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
    for source in files {
        let name = source
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("staged artifact is missing its filename"))?;
        let destination = output_dir.join(name);
        let mut temporary = NamedTempFile::new_in(output_dir)
            .with_context(|| format!("creating temporary file in {}", output_dir.display()))?;
        let mut input = File::open(&source)
            .with_context(|| format!("opening staged artifact {}", source.display()))?;
        io::copy(&mut input, temporary.as_file_mut())
            .with_context(|| format!("copying staged artifact {}", source.display()))?;
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
    if !archive.is_file() {
        bail!("staged manufacturing package did not contain {ARCHIVE_NAME}");
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

fn write_bom(path: &Path, parts: &[ManufacturingPart]) -> Result<()> {
    let mut groups = BTreeMap::<(String, String, String, String, String), Vec<String>>::new();
    for part in parts.iter().filter(|part| part.in_bom) {
        groups
            .entry((
                part.value.clone(),
                part.footprint.clone(),
                part.mpn.clone().unwrap_or_default(),
                part.side.clone(),
                if part.smd { "SMD" } else { "THT" }.to_string(),
            ))
            .or_default()
            .push(part.reference.clone());
    }
    let mut output = String::from("Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n");
    for ((value, footprint, mpn, side, kind), mut references) in groups {
        references.sort();
        let designators = references.join(",");
        let quantity = references.len().to_string();
        write_csv_row(
            &mut output,
            &[
                &value,
                &designators,
                &footprint,
                &quantity,
                &mpn,
                &side,
                &kind,
            ],
        );
    }
    fs::write(path, output).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_cpl(path: &Path, parts: &[ManufacturingPart]) -> Result<()> {
    let mut output = String::from("Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n");
    let mut placed = parts.iter().filter(|part| part.in_pos).collect::<Vec<_>>();
    placed.sort_unstable_by(|left, right| left.reference.cmp(&right.reference));
    for part in placed {
        let x = format_mm(part.x_nm);
        let y = format_mm(part.y_nm);
        let rotation = format_mdeg(part.rotation_mdeg);
        write_csv_row(
            &mut output,
            &[&part.reference, &x, &y, &rotation, &part.side],
        );
    }
    fs::write(path, output).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn write_csv_row(output: &mut String, values: &[&str]) {
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            output.push(',');
        }
        output.push_str(&csv_escape(value));
    }
    output.push('\n');
}

fn csv_escape(value: &str) -> String {
    if value
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\r' | '\n'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
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

fn directory_regular_files(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in
        fs::read_dir(directory).with_context(|| format!("listing {}", directory.display()))?
    {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            bail!(
                "manufacturing entry must be a regular file: {}",
                entry.path().display()
            );
        }
        files.push(entry.path());
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
}

fn validate_exported_artifacts(output_dir: &Path, artifacts: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut names = BTreeSet::new();
    let mut validated = Vec::with_capacity(artifacts.len());
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
        if is_reserved_name(name) {
            bail!("exported artifact uses reserved filename {name}");
        }
        if !names.insert(name.to_string()) {
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
        validated.push(path.clone());
    }
    validated.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(validated)
}

fn is_reserved_name(name: &str) -> bool {
    name == MANIFEST_NAME || name == ARCHIVE_NAME || GENERATED_CSV_NAMES.contains(&name)
}

fn is_manufacturing_artifact_name(name: &str) -> bool {
    if is_reserved_name(name) || name == "drc.rpt" {
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

fn descriptor_for_file(output_dir: &Path, path: &Path) -> Result<ArtifactDescriptor> {
    let name = path
        .strip_prefix(output_dir)
        .ok()
        .and_then(|relative| relative.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| anyhow::anyhow!("manufacturing artifact path is not portable"))?;
    let mut source = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let bytes = source
        .metadata()
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .len();
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .with_context(|| format!("hashing {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
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

fn write_zip(path: &Path, files: &[PathBuf]) -> Result<()> {
    let file = File::create(path).with_context(|| format!("creating {}", path.display()))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .compression_level(Some(6))
        .last_modified_time(zip::DateTime::default())
        .system(zip::System::Unix)
        .unix_permissions(0o644);
    for file_path in files {
        let name = file_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| anyhow::anyhow!("manufacturing artifact has an invalid filename"))?;
        zip.start_file(name, options)
            .with_context(|| format!("adding {name} to manufacturing archive"))?;
        let mut source =
            File::open(file_path).with_context(|| format!("opening {}", file_path.display()))?;
        io::copy(&mut source, &mut zip)
            .with_context(|| format!("writing {name} to manufacturing archive"))?;
    }
    zip.finish().context("finalizing manufacturing archive")?;
    Ok(())
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
            about_sha256: "about-digest".to_string(),
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
}
