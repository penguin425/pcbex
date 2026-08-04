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

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-circuit-kicad-{name}-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn path(value: &Path) -> &str {
    value.to_str().expect("test paths must be UTF-8")
}

fn handoff_schematic() -> String {
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

fn run_handoff(
    spec: &Path,
    schematic: &Path,
    policy: Option<&Path>,
    output: Option<&Path>,
    require_approved: bool,
) -> Output {
    let mut args = vec![
        "verify-circuit-kicad-handoff".to_string(),
        path(spec).to_string(),
        path(schematic).to_string(),
    ];
    if let Some(policy) = policy {
        args.extend(["--policy".into(), path(policy).into()]);
    }
    if let Some(output) = output {
        args.extend(["--output".into(), path(output).into()]);
    }
    if require_approved {
        args.push("--require-approved".into());
    }
    run(&args)
}

fn write_valid_inputs(directory: &Path) -> (PathBuf, PathBuf) {
    let spec = directory.join("circuit.json");
    let schematic = directory.join("design.kicad_sch");
    fs::write(&spec, CIRCUIT_SPEC).unwrap();
    fs::write(&schematic, handoff_schematic()).unwrap();
    (spec, schematic)
}

#[test]
fn verifies_approved_handoff_and_emits_closed_schema() {
    let directory = temp_dir("success");
    let (spec, schematic) = write_valid_inputs(&directory);
    let report_path = directory.join("handoff.json");
    let result = run_handoff(&spec, &schematic, None, Some(&report_path), true);
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
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["approved"], true);
    assert_eq!(report["counts"]["errors"], 0);
    assert!(report["findings"].as_array().unwrap().is_empty());
    for field in [
        "circuit_source_sha256",
        "schematic_source_sha256",
        "circuit_spec_sha256",
        "circuit_check_sha256",
        "schematic_sha256",
        "policy_sha256",
    ] {
        assert_eq!(report[field].as_str().unwrap().len(), 64, "{field}");
    }

    let stdout_result = run_handoff(&spec, &schematic, None, None, false);
    assert!(stdout_result.status.success());
    assert!(!stdout_result.stdout.is_empty());
    let stdout_report: Value = serde_json::from_slice(&stdout_result.stdout).unwrap();
    assert_eq!(stdout_report["approved"], true);

    let schema_path = directory.join("handoff.schema.json");
    let schema_result = run(&[
        "circuit-kicad-handoff-schema".into(),
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
    assert_eq!(
        schema["$defs"]["handoff_finding"]["additionalProperties"],
        false
    );
    assert_eq!(
        schema["$defs"]["electrical_review"]["additionalProperties"],
        false
    );

    let occupied = directory.join("occupied-schema.json");
    fs::write(&occupied, b"sentinel").unwrap();
    let collision = run(&[
        "circuit-kicad-handoff-schema".into(),
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
    let (spec, schematic) = write_valid_inputs(&directory);
    let mut changed = fs::read_to_string(&schematic).unwrap();
    changed = changed.replace("(property \"Value\" \"10k\"", "(property \"Value\" \"9k\"");
    fs::write(&schematic, changed).unwrap();
    let report_path = directory.join("rejected.json");
    let result = run_handoff(&spec, &schematic, None, Some(&report_path), true);
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&fs::read(&report_path).unwrap()).unwrap();
    assert_eq!(report["approved"], false);
    assert!(report["counts"]["errors"].as_u64().unwrap() > 0);
    assert!(!report["findings"].as_array().unwrap().is_empty());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_invalid_inputs_and_oversized_sources_before_output() {
    let directory = temp_dir("bounds");
    let (spec, schematic) = write_valid_inputs(&directory);
    let output = directory.join("report.json");

    fs::write(&spec, b"{}").unwrap();
    let invalid_spec = run_handoff(&spec, &schematic, None, Some(&output), false);
    assert!(!invalid_spec.status.success());
    assert!(!output.exists());
    fs::write(&spec, CIRCUIT_SPEC).unwrap();

    fs::write(&schematic, b"not a KiCad schematic").unwrap();
    let invalid_schematic = run_handoff(&spec, &schematic, None, Some(&output), false);
    assert!(!invalid_schematic.status.success());
    assert!(!output.exists());
    fs::write(&schematic, handoff_schematic()).unwrap();

    let policy = directory.join("policy.json");
    fs::write(&policy, b"{}").unwrap();
    let invalid_policy = run_handoff(&spec, &schematic, Some(&policy), Some(&output), false);
    assert!(!invalid_policy.status.success());
    assert!(!output.exists());

    fs::File::create(&spec)
        .unwrap()
        .set_len(pcbex_kicad::CIRCUIT_SPEC_V2_MAX_BYTES + 1)
        .unwrap();
    let oversized_spec = run_handoff(&spec, &schematic, None, Some(&output), false);
    assert!(!oversized_spec.status.success());
    assert!(!output.exists());
    fs::write(&spec, CIRCUIT_SPEC).unwrap();

    fs::File::create(&schematic)
        .unwrap()
        .set_len(pcbex_kicad::CIRCUIT_KICAD_HANDOFF_MAX_SCHEMATIC_BYTES + 1)
        .unwrap();
    let oversized_schematic = run_handoff(&spec, &schematic, None, Some(&output), false);
    assert!(!oversized_schematic.status.success());
    assert!(!output.exists());
    fs::write(&schematic, handoff_schematic()).unwrap();

    fs::File::create(&policy)
        .unwrap()
        .set_len(4 * 1024 * 1024 + 1)
        .unwrap();
    let oversized_policy = run_handoff(&spec, &schematic, Some(&policy), Some(&output), false);
    assert!(!oversized_policy.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn rejects_output_collisions_aliases_and_symlink_components() {
    let directory = temp_dir("outputs");
    let (spec, schematic) = write_valid_inputs(&directory);

    let occupied = directory.join("occupied.json");
    fs::write(&occupied, b"sentinel").unwrap();
    let collision = run_handoff(&spec, &schematic, None, Some(&occupied), false);
    assert!(!collision.status.success());
    assert_eq!(fs::read(&occupied).unwrap(), b"sentinel");

    let alias = run_handoff(&spec, &schematic, None, Some(&spec), false);
    assert!(!alias.status.success());
    assert_eq!(fs::read_to_string(&spec).unwrap(), CIRCUIT_SPEC);

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = directory.join("target.json");
        fs::write(&target, b"sentinel").unwrap();
        let direct = directory.join("direct-link.json");
        symlink(&target, &direct).unwrap();
        let direct_result = run_handoff(&spec, &schematic, None, Some(&direct), false);
        assert!(!direct_result.status.success());
        assert_eq!(fs::read(&target).unwrap(), b"sentinel");

        let linked_parent_target = directory.join("linked-parent-target");
        fs::create_dir_all(&linked_parent_target).unwrap();
        let linked_parent = directory.join("linked-parent");
        symlink(&linked_parent_target, &linked_parent).unwrap();
        let parent_result = run_handoff(
            &spec,
            &schematic,
            None,
            Some(&linked_parent.join("report.json")),
            false,
        );
        assert!(!parent_result.status.success());
        assert!(!linked_parent_target.join("report.json").exists());
    }

    fs::remove_dir_all(directory).unwrap();
}
