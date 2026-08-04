use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const CIRCUIT_SPEC: &str = r#"{
  "schema_version": 2,
  "parts": [
    {"reference":"U1","lib_id":"MCU:Chip","value":"Chip","footprint":"Package:QFN","mpn":null,"power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},"pins":[{"number":"1","name":"OUT","net":"SIGNAL","electrical_type":"output"},{"number":"2","name":"VCC","net":"VCC","electrical_type":"passive"}]},
    {"reference":"R1","lib_id":"Device:R","value":"10k","footprint":"Resistor_SMD:R_0603","mpn":null,"power":{"rail_voltage_uv":null,"max_voltage_uv":null,"requires_decoupling":false,"decoupling":false},"pins":[{"number":"1","name":"~","net":"SIGNAL","electrical_type":"passive"},{"number":"2","name":"~","net":"VCC","electrical_type":"passive"}]}
  ],
  "nets": [
    {"name":"SIGNAL","voltage_uv":null,"connections":[{"reference":"U1","pin":"1"},{"reference":"R1","pin":"1"}]},
    {"name":"VCC","voltage_uv":null,"connections":[{"reference":"U1","pin":"2"},{"reference":"R1","pin":"2"}]}
  ]
}"#;

const BOARD: &str = r#"(kicad_pcb
  (version 20250114)
  (generator pcbex-test)
  (general (thickness 1.6))
  (paper "A4")
  (layers
    (0 "F.Cu" signal)
    (31 "B.Cu" signal)
    (36 "B.SilkS" user "b.silkscreen")
    (37 "F.SilkS" user "f.silkscreen")
    (44 "Edge.Cuts" user))
  (setup (pad_to_mask_clearance 0))
  (net 0 "")
  (net 1 "SIGNAL")
  (net 2 "VCC")
  (footprint "Package:QFN"
    (layer "F.Cu")
    (at 10 10)
    (fp_text reference "U1" (at 0 0) (layer "F.Fab") hide)
    (fp_text value "Chip" (at 0 1) (layer "F.Fab") hide)
    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC")))
  (footprint "Resistor_SMD:R_0603"
    (layer "F.Cu")
    (at 20 10)
    (fp_text reference "R1" (at 0 0) (layer "F.Fab") hide)
    (fp_text value "10k" (at 0 1) (layer "F.Fab") hide)
    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC")))
  (gr_rect (start 0 0) (end 40 20) (stroke (width 0.05) (type default)) (fill none) (layer "Edge.Cuts")))"#;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-circuit-board-binding-{name}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn path(value: &Path) -> &str {
    value.to_str().expect("test paths must be UTF-8")
}

fn board_schematic() -> String {
    let mut source = include_str!("../../../examples/simple.kicad_sch").to_string();
    source = source.replace("(pin power_in line", "(pin passive line");
    source = source.replace(
        r##"  (no_connect
    (at 42.54 20)
    (uuid 00000000-0000-0000-0000-000000000015))"##,
        r##"  (global_label "VCC"
    (shape input)
    (at 42.54 20 0)
    (effects (font (size 1.27 1.27)) (justify left))
    (uuid 00000000-0000-0000-0000-000000000015)
    (property "Intersheetrefs" "${INTERSHEET_REFS}"
      (at 42.54 20 0)
      (effects (font (size 1.27 1.27)) hide)))"##,
    );
    source = source.replace(
        r##"    (property "Footprint" "Package:QFN"
      (at 12.54 20 0)
      (effects (font (size 1.27 1.27)) hide))"##,
        r##"    (property "Footprint" "Package:QFN"
      (at 12.54 20 0)
      (effects (font (size 1.27 1.27)) hide))
    (property "pcbex:requires_decoupling" "false")
    (property "pcbex:decoupling" "false")"##,
    );
    source = source.replace(
        r##"    (property "Footprint" "Resistor_SMD:R_0603"
      (at 40 20 0)
      (effects (font (size 1.27 1.27)) hide))"##,
        r##"    (property "Footprint" "Resistor_SMD:R_0603"
      (at 40 20 0)
      (effects (font (size 1.27 1.27)) hide))
    (property "pcbex:requires_decoupling" "false")
    (property "pcbex:decoupling" "false")"##,
    );
    source
}

fn run(args: &[String]) -> Output {
    Command::new(binary()).args(args).output().unwrap()
}

fn run_binding(
    spec: &Path,
    schematic: &Path,
    board: &Path,
    output: Option<&Path>,
    require_approved: bool,
) -> Output {
    let mut args = vec![
        "verify-circuit-kicad-board-binding".to_string(),
        path(spec).to_string(),
        path(schematic).to_string(),
        path(board).to_string(),
    ];
    if let Some(output) = output {
        args.extend(["--output".into(), path(output).into()]);
    }
    if require_approved {
        args.push("--require-approved".into());
    }
    run(&args)
}

fn write_valid_inputs(directory: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let spec = directory.join("circuit.json");
    let schematic = directory.join("design.kicad_sch");
    let board = directory.join("design.kicad_pcb");
    fs::write(&spec, CIRCUIT_SPEC).unwrap();
    fs::write(&schematic, board_schematic()).unwrap();
    fs::write(&board, BOARD).unwrap();
    (spec, schematic, board)
}

#[test]
fn verifies_board_binding_and_emits_closed_schema() {
    let directory = temp_dir("success");
    let (spec, schematic, board) = write_valid_inputs(&directory);
    let report_path = directory.join("binding.json");
    let result = run_binding(&spec, &schematic, &board, Some(&report_path), true);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        result.stdout.is_empty(),
        "output mode must not print report"
    );
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["approved"], true);
    assert_eq!(report["counts"]["errors"], 0);
    for field in [
        "board_source_sha256",
        "board_electrical_sha256",
        "circuit_kicad_handoff_sha256",
        "binding_sha256",
    ] {
        assert_eq!(report[field].as_str().unwrap().len(), 64, "{field}");
    }
    for field in ["circuit_source_sha256", "schematic_source_sha256"] {
        assert_eq!(
            report["circuit_kicad_handoff"][field]
                .as_str()
                .unwrap()
                .len(),
            64,
            "{field}"
        );
    }

    let stdout_result = run_binding(&spec, &schematic, &board, None, false);
    assert!(stdout_result.status.success());
    let stdout_report: Value = serde_json::from_slice(&stdout_result.stdout).unwrap();
    assert_eq!(stdout_report["approved"], true);

    let schema_path = directory.join("binding.schema.json");
    let schema_result = run(&[
        "circuit-kicad-board-binding-schema".into(),
        "--output".into(),
        path(&schema_path).into(),
    ]);
    assert!(
        schema_result.status.success(),
        "{}",
        String::from_utf8_lossy(&schema_result.stderr)
    );
    let schema: Value = serde_json::from_slice(&fs::read(&schema_path).unwrap()).unwrap();
    assert_eq!(schema["additionalProperties"], false);

    let occupied = directory.join("occupied-schema.json");
    fs::write(&occupied, b"sentinel").unwrap();
    let collision = run(&[
        "circuit-kicad-board-binding-schema".into(),
        "--output".into(),
        path(&occupied).into(),
    ]);
    assert!(!collision.status.success());
    assert_eq!(fs::read(&occupied).unwrap(), b"sentinel");
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn retains_rejected_report_before_require_approved_failure() {
    let directory = temp_dir("rejected");
    let (spec, schematic, board) = write_valid_inputs(&directory);
    let changed = BOARD.replace(
        r#"    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC")))
  (gr_rect"#,
        r#"    (pad "1" thru_hole circle (at 0 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 2 "VCC"))
    (pad "2" thru_hole circle (at 2 0) (size 1.5 1.5) (drill 0.8) (layers "*.Cu" "*.Mask") (net 1 "SIGNAL")))
  (gr_rect"#,
    );
    fs::write(&board, changed).unwrap();
    let report_path = directory.join("rejected.json");
    let result = run_binding(&spec, &schematic, &board, Some(&report_path), true);
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["approved"], false);
    assert!(report["counts"]["errors"].as_u64().unwrap() > 0);
    assert!(
        report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .all(|finding| finding["code"] == "pad_net_mismatch")
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn preflights_output_before_missing_input_and_rejects_aliases() {
    let directory = temp_dir("preflight");
    let (spec, schematic, board) = write_valid_inputs(&directory);
    let occupied = directory.join("occupied.json");
    fs::write(&occupied, b"sentinel").unwrap();
    let missing = directory.join("missing.json");
    let result = run_binding(&missing, &schematic, &board, Some(&occupied), false);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("existing output"));
    assert_eq!(fs::read(&occupied).unwrap(), b"sentinel");

    let alias = run_binding(&spec, &schematic, &board, Some(&spec), false);
    assert!(!alias.status.success());
    assert_eq!(fs::read_to_string(&spec).unwrap(), CIRCUIT_SPEC);

    let no_echo = run(&[
        "verify-circuit-kicad-board-binding".into(),
        path(&spec).into(),
        path(&schematic).into(),
        path(&board).into(),
        "--mcp-echo-report".into(),
    ]);
    assert!(!no_echo.status.success());
    assert!(String::from_utf8_lossy(&no_echo.stderr).contains("requires --output"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = directory.join("target.json");
        fs::write(&target, b"sentinel").unwrap();
        let direct = directory.join("direct-link.json");
        symlink(&target, &direct).unwrap();
        let direct_result = run_binding(&spec, &schematic, &board, Some(&direct), false);
        assert!(!direct_result.status.success());
        assert_eq!(fs::read(&target).unwrap(), b"sentinel");

        let parent_target = directory.join("linked-parent-target");
        fs::create_dir_all(&parent_target).unwrap();
        let parent = directory.join("linked-parent");
        symlink(&parent_target, &parent).unwrap();
        let parent_result = run_binding(
            &spec,
            &schematic,
            &board,
            Some(&parent.join("report.json")),
            false,
        );
        assert!(!parent_result.status.success());
        assert!(!parent_target.join("report.json").exists());
    }

    fs::remove_dir_all(directory).unwrap();
}
