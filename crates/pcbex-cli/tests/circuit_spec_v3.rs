use pcbex_kicad::{
    ElectricalPolicy, circuit_spec_v3_check_json_schema, circuit_spec_v3_json_schema,
    import_schematic, parse_circuit_spec_v3, verify_circuit_kicad_handoff,
};
use serde_json::Value;
use std::{fs, path::PathBuf, process::Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn example() -> PathBuf {
    repository_root().join("examples/circuit-board-spec-v3.json")
}

fn assert_success(output: std::process::Output) {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_closed(value: &Value) {
    match value {
        Value::Object(object) => {
            if object.get("type") == Some(&Value::String("object".into())) {
                assert_eq!(
                    object.get("additionalProperties"),
                    Some(&Value::Bool(false))
                );
            }
            for child in object.values() {
                assert_closed(child);
            }
        }
        Value::Array(values) => values.iter().for_each(assert_closed),
        _ => {}
    }
}

#[test]
fn v3_schemas_are_closed_unique_and_bounded() {
    let spec = circuit_spec_v3_json_schema();
    let check = circuit_spec_v3_check_json_schema();
    assert_eq!(
        spec["$id"],
        "https://github.com/penguin425/pcbex/schemas/circuit-spec-v3.json"
    );
    assert_eq!(
        check["$id"],
        "https://github.com/penguin425/pcbex/schemas/circuit-spec-v3-check-v2.json"
    );
    assert_eq!(spec["$defs"]["unit"]["properties"]["unit"]["maximum"], 255);
    assert_eq!(spec["$defs"]["part"]["properties"]["units"]["maxItems"], 32);
    assert_closed(&spec);
    assert_closed(&check);
}

#[test]
fn cli_checks_writes_and_verifies_multi_unit_handoff() {
    let directory = tempfile::tempdir().unwrap();
    let check_path = directory.path().join("check.json");
    let schematic_path = directory.path().join("multi.kicad_sch");
    let handoff_path = directory.path().join("handoff.json");
    assert_success(
        Command::new(binary())
            .args([
                "check-circuit-spec",
                example().to_str().unwrap(),
                "--output",
                check_path.to_str().unwrap(),
                "--require-approved",
            ])
            .output()
            .unwrap(),
    );
    let check: Value = serde_json::from_slice(&fs::read(&check_path).unwrap()).unwrap();
    assert_eq!(check["schema_version"], 2);
    assert_eq!(check["normalized_spec"]["schema_version"], 3);
    assert_eq!(check["electrical_review"]["approved"], true);

    assert_success(
        Command::new(binary())
            .args([
                "write-circuit-spec-kicad-schematic",
                example().to_str().unwrap(),
                "--output",
                schematic_path.to_str().unwrap(),
            ])
            .output()
            .unwrap(),
    );
    let schematic_source = fs::read_to_string(&schematic_path).unwrap();
    let imported = import_schematic(&schematic_source).unwrap();
    let u1_units = imported
        .symbols
        .iter()
        .filter(|symbol| symbol.reference == "U1")
        .map(|symbol| symbol.unit)
        .collect::<Vec<_>>();
    assert_eq!(u1_units, [1, 2]);

    assert_success(
        Command::new(binary())
            .args([
                "verify-circuit-kicad-handoff",
                example().to_str().unwrap(),
                schematic_path.to_str().unwrap(),
                "--output",
                handoff_path.to_str().unwrap(),
                "--require-approved",
            ])
            .output()
            .unwrap(),
    );
    let retained: Value = serde_json::from_slice(&fs::read(&handoff_path).unwrap()).unwrap();
    assert_eq!(retained["approved"], true);
    let report = verify_circuit_kicad_handoff(
        &fs::read_to_string(example()).unwrap(),
        &schematic_source,
        &ElectricalPolicy::default(),
    )
    .unwrap();
    assert!(report.approved, "{:?}", report.findings);
}

#[test]
fn v3_rejects_ambiguous_physical_pins_and_missing_nullable_keys() {
    let source = fs::read_to_string(example()).unwrap();
    let duplicate_pin = source.replacen(
        "{\"number\": \"2\", \"name\": \"VCC\"",
        "{\"number\": \"1\", \"name\": \"VCC\"",
        1,
    );
    assert!(
        parse_circuit_spec_v3(&duplicate_pin)
            .unwrap_err()
            .contains("reuses physical package pin")
    );
    let missing_mpn = source.replacen("      \"mpn\": null,\n", "", 1);
    assert!(parse_circuit_spec_v3(&missing_mpn).is_err());
    let missing_voltage = source.replacen("      \"voltage_uv\": null,\n", "", 1);
    assert!(parse_circuit_spec_v3(&missing_voltage).is_err());

    let mut too_many_physical_pins: Value = serde_json::from_str(&source).unwrap();
    let pins = too_many_physical_pins["parts"][0]["units"][0]["pins"]
        .as_array_mut()
        .unwrap();
    for number in 3..=257 {
        pins.push(serde_json::json!({
            "number": number.to_string(),
            "name": "NC",
            "net": null,
            "electrical_type": "no_connect"
        }));
    }
    assert!(
        parse_circuit_spec_v3(&serde_json::to_string(&too_many_physical_pins).unwrap())
            .unwrap_err()
            .contains("too many physical package pins")
    );
}

#[test]
fn cli_schema_commands_publish_v3_contracts_without_clobbering() {
    let directory = tempfile::tempdir().unwrap();
    for (command, name, expected_id) in [
        (
            "circuit-spec-v3-schema",
            "spec.json",
            "https://github.com/penguin425/pcbex/schemas/circuit-spec-v3.json",
        ),
        (
            "circuit-spec-v3-check-schema",
            "check.json",
            "https://github.com/penguin425/pcbex/schemas/circuit-spec-v3-check-v2.json",
        ),
    ] {
        let output = directory.path().join(name);
        assert_success(
            Command::new(binary())
                .args([command, "--output", output.to_str().unwrap()])
                .output()
                .unwrap(),
        );
        let schema: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        assert_eq!(schema["$id"], expected_id);
        let before = fs::read(&output).unwrap();
        let repeated = Command::new(binary())
            .args([command, "--output", output.to_str().unwrap()])
            .output()
            .unwrap();
        assert_success(repeated);
        assert_eq!(fs::read(&output).unwrap(), before);
    }
}
