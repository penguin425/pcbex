use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::{
    fs,
    io::{Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

const BOM: &[u8] = b"Comment,Designator,Footprint,Quantity,MPN,Layer,Type\n\
100nF,C1,Capacitor_SMD:C_0603_1608Metric,1,CC0603KRX7R9BB104,B,SMD\n\
10k,R2,Resistor_SMD:R_0603_1608Metric,1,RC0603FR-0710KL,F,SMD\n";
const CPL_HEADER: &str = "Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n";
const CANONICAL_CPL: &str = "Designator,Mid X (mm),Mid Y (mm),Rotation,Layer\n\
C1,-1.250000,2.000000,-45.500,B\n\
R2,12.345678,9.876543,90,F\n";

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(directory.path()).unwrap();
    (directory, canonical)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn board() -> Vec<u8> {
    br#"(kicad_pcb
  (version 20250114)
  (generator pcbex-final-cpl-test)
  (layers (0 "F.Cu" signal) (31 "B.Cu" signal))
  (footprint "Resistor_SMD:R_0603_1608Metric"
    (layer "F.Cu")
    (at 12.345678 9.876543 90)
    (property "Reference" "R2")
    (property "Value" "10k")
    (property "MPN" "RC0603FR-0710KL")
    (attr smd)
    (pad "1" smd rect (at 0 0) (size 1 1) (layers "F.Cu")))
  (footprint "Capacitor_SMD:C_0603_1608Metric"
    (layer "B.Cu")
    (at -1.25 2 -45.5)
    (property "Reference" "C1")
    (property "Value" "100nF")
    (property "MPN" "CC0603KRX7R9BB104")
    (attr smd)
    (pad "1" smd rect (at 0 0) (size 1 1) (layers "B.Cu"))))
"#
    .to_vec()
}

fn manufacturing_package(
    package_board_source: &[u8],
    cpl: &[u8],
    large_artifact_bytes: usize,
) -> Vec<u8> {
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
    let front_copper = if large_artifact_bytes == 0 {
        b"front-copper".to_vec()
    } else {
        vec![b'G'; large_artifact_bytes]
    };
    let artifacts = vec![
        ("board-F_Cu.gtl", front_copper),
        ("board-B_Cu.gbl", b"back-copper".to_vec()),
        ("board-f_mask.gts", b"front-mask".to_vec()),
        ("board-b_mask.gbs", b"back-mask".to_vec()),
        ("board-f_silkscreen.gto", b"front-legend".to_vec()),
        ("board-b_silkscreen.gbo", b"back-legend".to_vec()),
        ("board-Edge_Cuts.gm1", b"profile".to_vec()),
        ("board-job.gbrjob", job),
        ("board.drl", b"drill".to_vec()),
        ("drc.rpt", b"DRC clean".to_vec()),
        ("bom.csv", BOM.to_vec()),
        ("cpl.csv", cpl.to_vec()),
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
            "total": 2,
            "bom": 2,
            "placement": 2,
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
    Command::new(binary())
        .arg("verify-final-cpl")
        .arg(board)
        .arg(package)
        .args(arguments)
        .output()
        .unwrap()
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
fn process_has_open_path(process_id: u32, expected: &Path) -> bool {
    fs::read_dir(format!("/proc/{process_id}/fd"))
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|descriptor| {
            fs::read_link(descriptor.path())
                .map(|target| target == expected)
                .unwrap_or(false)
        })
}

fn write_inputs(directory: &Path, package_source: &[u8], cpl: &[u8]) -> (PathBuf, PathBuf) {
    let board_path = directory.join("board.kicad_pcb");
    let package_path = directory.join("manufacturing.zip");
    fs::write(&board_path, board()).unwrap();
    fs::write(&package_path, manufacturing_package(package_source, cpl, 0)).unwrap();
    (board_path, package_path)
}

#[test]
fn help_and_schema_publish_the_closed_final_cpl_contract() {
    let help = Command::new(binary())
        .args(["verify-final-cpl", "--help"])
        .output()
        .unwrap();
    assert_success(&help);
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(
        help.contains("verify-final-cpl [OPTIONS] <BOARD> <MANUFACTURING_ZIP>"),
        "help:\n{help}"
    );
    assert!(help.contains("--output <OUTPUT>"));
    assert!(help.contains("--require-approved"));

    let schema_output = Command::new(binary())
        .arg("final-cpl-report-schema")
        .output()
        .unwrap();
    assert_success(&schema_output);
    assert!(schema_output.stdout.ends_with(b"\n"));
    let schema: Value = serde_json::from_slice(&schema_output.stdout).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(
        schema["properties"]["scope"]["const"],
        "final_cpl_source_and_canonical_placement_v1"
    );
    assert_eq!(
        schema["required"],
        json!([
            "schema_version",
            "scope",
            "engine_version",
            "board_basename",
            "sources",
            "counts",
            "in_pos_parts",
            "findings",
            "approved"
        ])
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
            "cpl",
            "canonical_cpl",
            "package_board_source"
        ])
    );
    assert!(
        schema["properties"]["sources"]["properties"]
            .as_object()
            .unwrap()
            .values()
            .all(|identity| identity["additionalProperties"] == false)
    );
    assert_eq!(
        schema["properties"]["counts"]["additionalProperties"],
        false
    );
    assert_eq!(schema["properties"]["in_pos_parts"]["maxItems"], 256);
    assert_eq!(
        schema["properties"]["in_pos_parts"]["items"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["properties"]["in_pos_parts"]["items"]["required"],
        json!(["reference", "x_nm", "y_nm", "rotation_mdeg", "layer"])
    );
    assert!(
        schema["properties"]["findings"]["items"]["anyOf"]
            .as_array()
            .unwrap()
            .iter()
            .all(|branch| branch["additionalProperties"] == false)
    );
}

#[test]
fn approved_canonical_package_reports_exact_sorted_placements_and_no_paths() {
    let (_temporary, canonical_directory) = canonical_tempdir();
    let board_source = board();
    let (board_path, package_path) = write_inputs(
        &canonical_directory,
        &board_source,
        CANONICAL_CPL.as_bytes(),
    );

    let output = run_verify(&board_path, &package_path, &["--require-approved"]);
    assert_success(&output);
    assert!(output.stdout.ends_with(b"\n"));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(
        report["scope"],
        "final_cpl_source_and_canonical_placement_v1"
    );
    assert_eq!(report["approved"], true);
    assert_eq!(report["findings"], json!([]));
    assert_eq!(report["board_basename"], "board.kicad_pcb");
    assert_eq!(report["counts"]["board_parts"], 2);
    assert_eq!(report["counts"]["board_in_pos_parts"], 2);
    assert_eq!(report["counts"]["package_parts"], 2);
    assert_eq!(report["counts"]["package_placement_parts"], 2);
    assert_eq!(report["counts"]["findings"], 0);
    assert_eq!(report["sources"]["board"]["bytes"], board_source.len());
    assert_eq!(report["sources"]["board"]["sha256"], sha256(&board_source));
    assert_eq!(
        report["sources"]["board"],
        report["sources"]["package_board_source"]
    );
    assert_eq!(report["sources"]["cpl"], report["sources"]["canonical_cpl"]);
    assert_eq!(
        report["in_pos_parts"],
        json!([
            {
                "reference": "C1",
                "x_nm": -1_250_000,
                "y_nm": 2_000_000,
                "rotation_mdeg": -45_500,
                "layer": "B"
            },
            {
                "reference": "R2",
                "x_nm": 12_345_678,
                "y_nm": 9_876_543,
                "rotation_mdeg": 90_000,
                "layer": "F"
            }
        ])
    );
    let rendered = String::from_utf8(output.stdout).unwrap();
    assert!(!rendered.contains(canonical_directory.to_string_lossy().as_ref()));
}

#[test]
fn source_only_cpl_only_and_dual_mismatches_are_retained_in_stable_order() {
    let (_temporary, directory) = canonical_tempdir();
    let board_source = board();
    let board_path = directory.join("board.kicad_pcb");
    fs::write(&board_path, &board_source).unwrap();
    let mut other_source = board_source.clone();
    other_source.extend_from_slice(b"\n");
    let numeric_equivalent =
        format!("{CPL_HEADER}C1,-1.25,2,-45.5,B\nR2,12.345678,9.876543,90.0,F\n");

    let source_package = directory.join("source-only.zip");
    fs::write(
        &source_package,
        manufacturing_package(&other_source, CANONICAL_CPL.as_bytes(), 0),
    )
    .unwrap();
    let source_output = run_verify(&board_path, &source_package, &[]);
    assert_success(&source_output);
    let source_report: Value = serde_json::from_slice(&source_output.stdout).unwrap();
    assert_eq!(source_report["approved"], false);
    assert_eq!(
        source_report["findings"],
        json!([{
            "code": "package_board_source_mismatch",
            "message": "manufacturing package input identity does not equal the supplied board"
        }])
    );
    assert_eq!(
        source_report["sources"]["cpl"],
        source_report["sources"]["canonical_cpl"]
    );

    let cpl_package = directory.join("cpl-only.zip");
    fs::write(
        &cpl_package,
        manufacturing_package(&board_source, numeric_equivalent.as_bytes(), 0),
    )
    .unwrap();
    let cpl_output = run_verify(&board_path, &cpl_package, &[]);
    assert_success(&cpl_output);
    let cpl_report: Value = serde_json::from_slice(&cpl_output.stdout).unwrap();
    assert_eq!(cpl_report["approved"], false);
    assert_eq!(cpl_report["findings"][0]["code"], "canonical_cpl_mismatch");
    assert_ne!(
        cpl_report["sources"]["cpl"],
        cpl_report["sources"]["canonical_cpl"]
    );
    assert_eq!(
        cpl_report["sources"]["board"],
        cpl_report["sources"]["package_board_source"]
    );

    let dual_package = directory.join("dual.zip");
    fs::write(
        &dual_package,
        manufacturing_package(&other_source, numeric_equivalent.as_bytes(), 0),
    )
    .unwrap();
    let dual_output = run_verify(&board_path, &dual_package, &[]);
    assert_success(&dual_output);
    let dual_report: Value = serde_json::from_slice(&dual_output.stdout).unwrap();
    assert_eq!(dual_report["approved"], false);
    assert_eq!(dual_report["counts"]["findings"], 2);
    assert_eq!(
        dual_report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["code"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["canonical_cpl_mismatch", "package_board_source_mismatch"]
    );
}

#[test]
fn valid_equivalent_row_order_and_numeric_spelling_are_exact_byte_mismatches() {
    let (_temporary, directory) = canonical_tempdir();
    let board_source = board();
    let board_path = directory.join("board.kicad_pcb");
    fs::write(&board_path, &board_source).unwrap();
    let variants = [
        format!("{CPL_HEADER}R2,12.345678,9.876543,90,F\nC1,-1.250000,2.000000,-45.500,B\n"),
        format!("{CPL_HEADER}C1,-1.25,2,-45.5,B\nR2,12.345678,9.876543,90.0,F\n"),
    ];
    for (index, variant) in variants.iter().enumerate() {
        let package_path = directory.join(format!("variant-{index}.zip"));
        fs::write(
            &package_path,
            manufacturing_package(&board_source, variant.as_bytes(), 0),
        )
        .unwrap();
        let output = run_verify(&board_path, &package_path, &[]);
        assert_success(&output);
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["approved"], false, "variant {index}");
        assert_eq!(
            report["findings"][0]["code"], "canonical_cpl_mismatch",
            "variant {index}"
        );
        assert_ne!(
            report["sources"]["cpl"], report["sources"]["canonical_cpl"],
            "variant {index}"
        );
        assert_eq!(report["in_pos_parts"].as_array().unwrap().len(), 2);
    }
}

#[test]
fn malformed_board_package_and_cpl_are_hard_errors_without_a_report() {
    let (_temporary, directory) = canonical_tempdir();
    let board_source = board();
    let board_path = directory.join("board.kicad_pcb");
    let package_path = directory.join("manufacturing.zip");
    let output_path = directory.join("report.json");
    fs::write(&board_path, &board_source).unwrap();
    fs::write(&package_path, b"not-a-zip").unwrap();

    let invalid_zip = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!invalid_zip.status.success());
    assert!(invalid_zip.stdout.is_empty());
    assert!(!output_path.exists());

    fs::write(
        &package_path,
        manufacturing_package(&board_source, b"wrong,header\n", 0),
    )
    .unwrap();
    let invalid_cpl = run_verify(
        &board_path,
        &package_path,
        &["--output", output_path.to_str().unwrap()],
    );
    assert!(!invalid_cpl.status.success());
    assert!(invalid_cpl.stdout.is_empty());
    assert!(!output_path.exists());
    assert!(String::from_utf8_lossy(&invalid_cpl.stderr).contains("cpl.csv"));

    fs::write(&board_path, b"not a KiCad board").unwrap();
    fs::write(
        &package_path,
        manufacturing_package(&board_source, CANONICAL_CPL.as_bytes(), 0),
    )
    .unwrap();
    let invalid_board = run_verify(
        &board_path,
        &package_path,
        &["--output", output_path.to_str().unwrap()],
    );
    assert!(!invalid_board.status.success());
    assert!(invalid_board.stdout.is_empty());
    assert!(!output_path.exists());
}

#[test]
fn no_clobber_alias_links_symlinks_and_final_gate_fail_closed() {
    let (_temporary, directory) = canonical_tempdir();
    let board_source = board();
    let (board_path, package_path) =
        write_inputs(&directory, &board_source, CANONICAL_CPL.as_bytes());
    let report_path = directory.join("report.json");
    let sentinel = b"preserve-existing-report\n";
    fs::write(&report_path, sentinel).unwrap();

    let existing = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(!existing.status.success());
    assert!(existing.stdout.is_empty());
    assert_eq!(fs::read(&report_path).unwrap(), sentinel);
    assert!(String::from_utf8_lossy(&existing.stderr).contains("refusing to overwrite"));

    let preflight = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(directory.join("missing-board.kicad_pcb"))
        .arg(directory.join("missing-package.zip"))
        .arg("--output")
        .arg(&report_path)
        .output()
        .unwrap();
    assert!(!preflight.status.success());
    assert_eq!(fs::read(&report_path).unwrap(), sentinel);
    let preflight_stderr = String::from_utf8(preflight.stderr).unwrap();
    assert!(preflight_stderr.contains("refusing to overwrite"));
    assert!(!preflight_stderr.contains("reading final CPL board"));

    let original_board = fs::read(&board_path).unwrap();
    let board_alias = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&board_path)
        .output()
        .unwrap();
    assert!(!board_alias.status.success());
    assert_eq!(fs::read(&board_path).unwrap(), original_board);
    assert!(String::from_utf8_lossy(&board_alias.stderr).contains("must not alias an input"));

    let hard_link = directory.join("hard-link-report.json");
    fs::hard_link(&board_path, &hard_link).unwrap();
    let hard_link_output = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&hard_link)
        .output()
        .unwrap();
    assert!(!hard_link_output.status.success());
    assert_eq!(fs::read(&hard_link).unwrap(), original_board);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let symlink_output = directory.join("symlink-report.json");
        symlink(&report_path, &symlink_output).unwrap();
        let result = Command::new(binary())
            .arg("verify-final-cpl")
            .arg(&board_path)
            .arg(&package_path)
            .arg("--output")
            .arg(&symlink_output)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(fs::read(&report_path).unwrap(), sentinel);
        assert!(String::from_utf8_lossy(&result.stderr).contains("symlink"));

        let symlinked_board = directory.join("board-link.kicad_pcb");
        symlink(&board_path, &symlinked_board).unwrap();
        let input_report = directory.join("input-link-report.json");
        let result = Command::new(binary())
            .arg("verify-final-cpl")
            .arg(&symlinked_board)
            .arg(&package_path)
            .arg("--output")
            .arg(&input_report)
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!input_report.exists());
        assert!(String::from_utf8_lossy(&result.stderr).contains("symlink"));

        let real_parent = directory.join("real-parent");
        fs::create_dir(&real_parent).unwrap();
        let linked_parent = directory.join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let result = Command::new(binary())
            .arg("verify-final-cpl")
            .arg(&board_path)
            .arg(&package_path)
            .arg("--output")
            .arg(linked_parent.join("report.json"))
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(!real_parent.join("report.json").exists());
        assert!(String::from_utf8_lossy(&result.stderr).contains("symlink"));
    }

    let mismatch_cpl = format!("{CPL_HEADER}C1,-1.25,2,-45.5,B\nR2,12.345678,9.876543,90,F\n");
    let mismatch_package = directory.join("mismatch.zip");
    fs::write(
        &mismatch_package,
        manufacturing_package(&board_source, mismatch_cpl.as_bytes(), 0),
    )
    .unwrap();
    let gate_report = directory.join("gate-report.json");
    let gated = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&mismatch_package)
        .arg("--output")
        .arg(&gate_report)
        .arg("--require-approved")
        .output()
        .unwrap();
    assert!(!gated.status.success());
    assert!(gated.stdout.is_empty());
    let retained: Value = serde_json::from_slice(&fs::read(&gate_report).unwrap()).unwrap();
    assert_eq!(retained["approved"], false);
    assert_eq!(retained["findings"][0]["code"], "canonical_cpl_mismatch");
    let stderr = String::from_utf8(gated.stderr).unwrap();
    assert!(stderr.contains("final CPL verification rejected"));
    assert!(!stderr.contains(directory.to_string_lossy().as_ref()));
}

#[test]
fn schema_output_is_lf_terminated_and_never_clobbers() {
    let (_temporary, directory) = canonical_tempdir();
    let schema_path = directory.join("schema.json");
    let first = Command::new(binary())
        .arg("final-cpl-report-schema")
        .arg("--output")
        .arg(&schema_path)
        .output()
        .unwrap();
    assert_success(&first);
    let schema = fs::read(&schema_path).unwrap();
    assert!(schema.ends_with(b"\n"));
    serde_json::from_slice::<Value>(&schema).unwrap();

    let second = Command::new(binary())
        .arg("final-cpl-report-schema")
        .arg("--output")
        .arg(&schema_path)
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert_eq!(fs::read(&schema_path).unwrap(), schema);
}

#[test]
fn more_than_256_placement_references_is_a_hard_error_before_package_use() {
    let (_temporary, directory) = canonical_tempdir();
    let board_path = directory.join("large.kicad_pcb");
    let package_path = directory.join("not-read.zip");
    let output_path = directory.join("report.json");
    let mut source = String::from("(kicad_pcb\n");
    for index in 1..=257 {
        source.push_str(&format!(
            "(footprint \"Test:R\" (layer \"F.Cu\") (at 0 0) (property \"Reference\" \"R{index}\") (property \"Value\" \"1k\") (attr smd))\n"
        ));
    }
    source.push_str(")\n");
    fs::write(&board_path, source).unwrap();
    fs::write(&package_path, b"not-a-package").unwrap();

    let output = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&output_path)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!output_path.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("more than 256 placement references"));
}

#[cfg(target_os = "linux")]
#[test]
fn final_source_reread_rejects_board_replacement_before_publication() {
    use std::{thread, time::Duration};

    let (_temporary, directory) = canonical_tempdir();
    let board_source = board();
    let board_path = directory.join("board.kicad_pcb");
    let replacement_path = directory.join("replacement.kicad_pcb");
    let package_path = directory.join("manufacturing.zip");
    let report_path = directory.join("report.json");
    fs::write(&board_path, &board_source).unwrap();
    let mut replacement = board_source.clone();
    replacement.extend_from_slice(b"\n");
    fs::write(&replacement_path, replacement).unwrap();
    fs::write(
        &package_path,
        manufacturing_package(&board_source, CANONICAL_CPL.as_bytes(), 32 * 1024 * 1024),
    )
    .unwrap();

    let mut child = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&report_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let package_path = fs::canonicalize(&package_path).unwrap();
    let mut observed_package_read = false;
    for _ in 0..20_000 {
        observed_package_read = process_has_open_path(child.id(), &package_path);
        if observed_package_read {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_micros(100));
    }
    assert!(
        observed_package_read,
        "did not observe the bounded package capture"
    );
    fs::rename(&replacement_path, &board_path).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(!report_path.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("final CPL board changed during final source revalidation")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn final_source_reread_rejects_package_replacement_before_publication() {
    use std::{thread, time::Duration};

    let (_temporary, directory) = canonical_tempdir();
    let board_source = board();
    let board_path = directory.join("board.kicad_pcb");
    let package_path = directory.join("manufacturing.zip");
    let replacement_path = directory.join("replacement.zip");
    let report_path = directory.join("report.json");
    fs::write(&board_path, &board_source).unwrap();
    let package = manufacturing_package(&board_source, CANONICAL_CPL.as_bytes(), 32 * 1024 * 1024);
    fs::write(&package_path, &package).unwrap();
    let mut replacement = package;
    replacement.push(0);
    fs::write(&replacement_path, replacement).unwrap();

    let mut child = Command::new(binary())
        .arg("verify-final-cpl")
        .arg(&board_path)
        .arg(&package_path)
        .arg("--output")
        .arg(&report_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let package_path = fs::canonicalize(&package_path).unwrap();
    let mut observed_package_read = false;
    for _ in 0..20_000 {
        observed_package_read = process_has_open_path(child.id(), &package_path);
        if observed_package_read {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_micros(100));
    }
    assert!(
        observed_package_read,
        "did not observe the bounded package capture"
    );

    let mut observed_capture_close = false;
    for _ in 0..20_000 {
        observed_capture_close = !process_has_open_path(child.id(), &package_path);
        if observed_capture_close {
            break;
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        thread::sleep(Duration::from_micros(100));
    }
    assert!(
        observed_capture_close,
        "initial bounded package capture did not close"
    );
    fs::rename(&replacement_path, &package_path).unwrap();

    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(!report_path.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("final CPL manufacturing package changed during final source revalidation")
    );
}
