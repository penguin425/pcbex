//! Factory-ready BOM, pick-and-place, manifest, and archive generation.

use anyhow::{Context, Result};
use pcbex_kicad::ManufacturingPart;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

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
    input: ArtifactDescriptor,
    parts: ManufacturingCounts,
    artifacts: Vec<ArtifactDescriptor>,
    archive: String,
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
    parts: &[ManufacturingPart],
    drc_report: Option<&Path>,
) -> Result<PathBuf> {
    fs::create_dir_all(output_dir).with_context(|| format!("creating {}", output_dir.display()))?;
    write_bom(&output_dir.join("bom.csv"), parts)?;
    write_cpl(&output_dir.join("cpl.csv"), parts)?;
    if let Some(report) = drc_report.filter(|path| path.is_file()) {
        let destination = output_dir.join("drc.rpt");
        if report != destination {
            fs::copy(report, &destination)
                .with_context(|| format!("copying KiCad DRC report from {}", report.display()))?;
        }
    }

    let archive_name = "manufacturing.zip";
    let archive_path = output_dir.join(archive_name);
    let mut artifacts = collect_artifacts(output_dir, Some(&archive_path))?;
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = ManufacturingManifest {
        schema_version: 1,
        engine: "pcbex",
        engine_version: env!("CARGO_PKG_VERSION"),
        input: descriptor_for_bytes(&input_path.display().to_string(), input_bytes),
        parts: ManufacturingCounts {
            total: parts.len(),
            bom: parts.iter().filter(|part| part.in_bom).count(),
            placement: parts.iter().filter(|part| part.in_pos).count(),
            dnp: parts.iter().filter(|part| part.dnp).count(),
        },
        artifacts,
        archive: archive_name.to_string(),
    };
    let manifest_path = output_dir.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    fs::write(&manifest_path, &manifest_bytes)
        .with_context(|| format!("writing {}", manifest_path.display()))?;

    let files = collect_files(output_dir, Some(&archive_path))?;
    write_zip(&archive_path, &files)?;
    Ok(archive_path)
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
    for part in parts.iter().filter(|part| part.in_pos) {
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
    format!("{:.6}", value_nm as f64 / 1_000_000.0)
}

fn format_mdeg(value_mdeg: i64) -> String {
    let value = value_mdeg as f64 / 1_000.0;
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        format!("{value:.3}")
    }
}

fn collect_artifacts(
    output_dir: &Path,
    excluded: Option<&Path>,
) -> Result<Vec<ArtifactDescriptor>> {
    collect_files(output_dir, excluded)?
        .into_iter()
        .filter(|path| path.file_name().and_then(|name| name.to_str()) != Some("manifest.json"))
        .map(|path| {
            let bytes = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            Ok(descriptor_for_bytes(
                &path
                    .strip_prefix(output_dir)
                    .unwrap_or(&path)
                    .to_string_lossy(),
                &bytes,
            ))
        })
        .collect()
}

fn collect_files(output_dir: &Path, excluded: Option<&Path>) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in
        fs::read_dir(output_dir).with_context(|| format!("listing {}", output_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || excluded.is_some_and(|excluded| path == excluded) {
            continue;
        }
        files.push(path);
    }
    files.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    Ok(files)
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
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
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
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn writes_grouped_bom_and_placement_archive() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("pcbex-manufacturing-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        let parts = vec![
            part("R2", "10k", true, true, true),
            part("R1", "10k", true, true, true),
            part("H1", "Mount", false, false, false),
        ];
        let archive = write_manufacturing_package(
            &path,
            Path::new("board.kicad_pcb"),
            b"board",
            &parts,
            None,
        )
        .unwrap();
        let bom = fs::read_to_string(path.join("bom.csv")).unwrap();
        assert!(bom.contains("R1,R2"));
        let cpl = fs::read_to_string(path.join("cpl.csv")).unwrap();
        assert!(cpl.contains("R1,1.250000,2.500000,90,F"));
        assert!(archive.is_file());
        assert!(fs::metadata(path.join("manifest.json")).unwrap().len() > 0);
        fs::remove_dir_all(path).unwrap();
    }
}
