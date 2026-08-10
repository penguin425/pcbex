use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const BOM_HEADER: &str = "Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn board(value: &str) -> Vec<u8> {
    format!(
        r#"(kicad_pcb
  (version 20250114)
  (generator pcbex-final-bom-test)
  (layers (0 "F.Cu" signal) (31 "B.Cu" signal))
  (footprint "Resistor_SMD:R_0603_1608Metric"
    (layer "F.Cu")
    (at 1 2 0)
    (property "Reference" "R1")
    (property "Value" "{value}")
    (property "MPN" "RC0603FR-0710KL")
    (attr smd)
    (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu"))))
"#
    )
    .into_bytes()
}

fn canonical_bom(value: &str) -> Vec<u8> {
    format!("{BOM_HEADER}{value},R1,Resistor_SMD:R_0603_1608Metric,1,RC0603FR-0710KL,F,SMD\n")
        .into_bytes()
}

fn manufacturing_package(package_board_source: &[u8], bom: Vec<u8>, bom_parts: u64) -> Vec<u8> {
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
    let cpl = if bom_parts == 0 {
        b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n".to_vec()
    } else {
        b"Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\nR1,1,2,0,F\n".to_vec()
    };
    let artifacts = vec![
        ("board-F_Cu.gtl", b"front-copper".to_vec()),
        ("board-B_Cu.gbl", b"back-copper".to_vec()),
        ("board-f_mask.gts", b"front-mask".to_vec()),
        ("board-b_mask.gbs", b"back-mask".to_vec()),
        ("board-f_silkscreen.gto", b"front-legend".to_vec()),
        ("board-b_silkscreen.gbo", b"back-legend".to_vec()),
        ("board-Edge_Cuts.gm1", b"profile".to_vec()),
        ("board-job.gbrjob", job),
        ("board.drl", b"drill".to_vec()),
        ("drc.rpt", b"DRC clean".to_vec()),
        ("bom.csv", bom),
        ("cpl.csv", cpl),
    ];
    let manifest = serde_json::to_vec(&json!({
        "schema_version": 1,
        "engine": "pcbex",
        "engine_version": env!("CARGO_PKG_VERSION"),
        "tools": {
            "kicad_cli": "10.0.5",
            "kicad_cli_about_sha256": "a".repeat(64)
        },
        "input": {
            "path": "board.kicad_pcb",
            "bytes": package_board_source.len(),
            "sha256": sha256(package_board_source)
        },
        "project_inputs": [],
        "parts": {
            "total": bom_parts,
            "bom": bom_parts,
            "placement": bom_parts,
            "dnp": 0
        },
        "artifacts": artifacts.iter().map(|(path, bytes)| json!({
            "path": path,
            "bytes": bytes.len(),
            "sha256": sha256(bytes)
        })).collect::<Vec<_>>(),
        "archive": "manufacturing.zip"
    }))
    .unwrap();

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (path, bytes) in artifacts {
        writer.start_file(path, options).unwrap();
        writer.write_all(&bytes).unwrap();
    }
    writer.start_file("manifest.json", options).unwrap();
    writer.write_all(&manifest).unwrap();
    writer.finish().unwrap().into_inner()
}

fn run_verify(board: &Path, package: &Path, arguments: &[&str]) -> Output {
    let mut command = Command::new(binary());
    command
        .arg("verify-final-bom")
        .arg(board)
        .arg(package)
        .args(arguments);
    command.output().unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn schema_and_approved_report_are_closed_exact_and_path_free() {
    let schema_output = Command::new(binary())
        .arg("final-bom-report-schema")
        .output()
        .unwrap();
    assert_success(&schema_output);
    let schema: Value = serde_json::from_slice(&schema_output.stdout).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["scope"]["const"],
        "final_bom_source_and_canonical_bom_v1"
    );
    assert_eq!(
        schema["properties"]["sources"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["sources"]["required"],
        json!([
            "board",
            "manufacturing_package",
            "manifest",
            "bom",
            "canonical_bom",
            "package_board_source"
        ])
    );
    assert_eq!(schema["properties"]["in_bom_parts"]["maxItems"], 256);

    let temporary = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(temporary.path()).unwrap();
    let board_source = board("10k");
    let board_path = canonical.join("board.kicad_pcb");
    let package_path = canonical.join("manufacturing.zip");
    fs::write(&board_path, &board_source).unwrap();
    fs::write(
        &package_path,
        manufacturing_package(&board_source, canonical_bom("10k"), 1),
    )
    .unwrap();

    let output = run_verify(&board_path, &package_path, &["--require-approved"]);
    assert_success(&output);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["approved"], true);
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["counts"]["board_parts"], 1);
    assert_eq!(report["counts"]["board_in_bom_parts"], 1);
    assert_eq!(report["counts"]["package_parts"], 1);
    assert_eq!(report["counts"]["package_in_bom_parts"], 1);
    assert_eq!(report["board_basename"], "board.kicad_pcb");
    assert_eq!(report["sources"]["board"]["bytes"], board_source.len());
    assert_eq!(report["sources"]["board"]["sha256"], sha256(&board_source));
    assert_eq!(
        report["sources"]["board"],
        report["sources"]["package_board_source"]
    );
    assert_eq!(report["sources"]["bom"], report["sources"]["canonical_bom"]);
    assert_eq!(
        report["in_bom_parts"],
        json!([{
            "reference": "R1",
            "value": "10k",
            "footprint": "Resistor_SMD:R_0603_1608Metric",
            "mpn": "RC0603FR-0710KL",
            "layer": "F",
            "type": "SMD"
        }])
    );
    assert!(report["in_bom_parts"][0].get("quantity").is_none());
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(canonical.to_string_lossy().as_ref())
    );
    assert!(output.stdout.ends_with(b"\n"));
}

#[test]
fn valid_mismatches_are_retained_before_the_optional_approval_gate() {
    let temporary = tempfile::tempdir().unwrap();
    let board_source = board("10k");
    let board_path = temporary.path().join("board.kicad_pcb");
    fs::write(&board_path, &board_source).unwrap();

    let source_mismatch = temporary.path().join("source-mismatch.zip");
    let mut other_source = board_source.clone();
    other_source.extend_from_slice(b"\n");
    fs::write(
        &source_mismatch,
        manufacturing_package(&other_source, canonical_bom("10k"), 1),
    )
    .unwrap();
    let source_report_path = temporary.path().join("source-report.json");
    let source_output = Command::new(binary())
        .arg("verify-final-bom")
        .arg(&board_path)
        .arg(&source_mismatch)
        .args(["--output"])
        .arg(&source_report_path)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert!(!source_output.status.success());
    let source_report: Value =
        serde_json::from_slice(&fs::read(&source_report_path).unwrap()).unwrap();
    assert_eq!(source_report["approved"], false);
    assert_eq!(
        source_report["findings"][0]["code"],
        "package_board_source_mismatch"
    );
    assert_eq!(
        source_report["sources"]["bom"],
        source_report["sources"]["canonical_bom"]
    );

    let bom_mismatch = temporary.path().join("bom-mismatch.zip");
    fs::write(
        &bom_mismatch,
        manufacturing_package(&board_source, canonical_bom("22k"), 1),
    )
    .unwrap();
    let bom_output = run_verify(&board_path, &bom_mismatch, &[]);
    assert_success(&bom_output);
    let bom_report: Value = serde_json::from_slice(&bom_output.stdout).unwrap();
    assert_eq!(bom_report["approved"], false);
    assert_eq!(bom_report["findings"][0]["code"], "canonical_bom_mismatch");
    assert_ne!(
        bom_report["sources"]["bom"],
        bom_report["sources"]["canonical_bom"]
    );
    assert_eq!(
        bom_report["sources"]["board"],
        bom_report["sources"]["package_board_source"]
    );

    let both_mismatch = temporary.path().join("both-mismatch.zip");
    fs::write(
        &both_mismatch,
        manufacturing_package(&other_source, canonical_bom("22k"), 1),
    )
    .unwrap();
    let both_output = run_verify(&board_path, &both_mismatch, &[]);
    assert_success(&both_output);
    let both_report: Value = serde_json::from_slice(&both_output.stdout).unwrap();
    assert_eq!(both_report["counts"]["findings"], 2);
    assert_eq!(
        both_report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["canonical_bom_mismatch", "package_board_source_mismatch"]
    );
}

#[test]
fn malformed_inputs_and_existing_outputs_never_publish_or_clobber() {
    let temporary = tempfile::tempdir().unwrap();
    let board_path = temporary.path().join("board.kicad_pcb");
    let package_path = temporary.path().join("manufacturing.zip");
    let output_path = temporary.path().join("report.json");
    fs::write(&board_path, board("10k")).unwrap();
    fs::write(&package_path, b"not-a-zip").unwrap();

    let malformed = Command::new(binary())
        .arg("verify-final-bom")
        .arg(&board_path)
        .arg(&package_path)
        .args(["--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!malformed.status.success());
    assert!(!output_path.exists());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("valid ZIP archive"));

    let sentinel = b"preserve-existing-report\n";
    fs::write(&output_path, sentinel).unwrap();
    let existing = Command::new(binary())
        .arg("verify-final-bom")
        .arg(&board_path)
        .arg(&package_path)
        .args(["--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!existing.status.success());
    assert_eq!(fs::read(&output_path).unwrap(), sentinel);
    assert!(String::from_utf8_lossy(&existing.stderr).contains("refusing to overwrite"));
}

#[test]
fn more_than_256_bom_references_is_a_hard_error() {
    let temporary = tempfile::tempdir().unwrap();
    let board_path = temporary.path().join("large.kicad_pcb");
    let package_path = temporary.path().join("manufacturing.zip");
    let output_path = temporary.path().join("report.json");
    let mut source = String::from(
        "(kicad_pcb (version 20250114) (layers (0 \"F.Cu\" signal) (31 \"B.Cu\" signal))\n",
    );
    for index in 1..=257 {
        source.push_str(&format!(
            "(footprint \"Test:R\" (layer \"F.Cu\") (at 0 0) (property \"Reference\" \"R{index}\") (property \"Value\" \"1k\") (attr smd))\n"
        ));
    }
    source.push_str(")\n");
    fs::write(&board_path, source).unwrap();
    fs::write(&package_path, b"not-read-after-reference-bound").unwrap();

    let output = Command::new(binary())
        .arg("verify-final-bom")
        .arg(&board_path)
        .arg(&package_path)
        .args(["--output"])
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!output_path.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("more than 256 BOM references"));
}
