use pcbex_kicad::{
    CircuitConnectionV2, CircuitNetV2, CircuitPartV2, CircuitPinV2, CircuitPowerV2, CircuitSpecV2,
    ElectricalPinType, check_circuit_spec, circuit_spec_check_json_schema,
    circuit_spec_v2_json_schema, normalize_circuit_spec_v2,
};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-circuit-spec-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

fn power(
    rail_voltage_uv: Option<i64>,
    max_voltage_uv: Option<i64>,
    requires_decoupling: bool,
    decoupling: bool,
) -> CircuitPowerV2 {
    CircuitPowerV2 {
        rail_voltage_uv,
        max_voltage_uv,
        requires_decoupling,
        decoupling,
    }
}

fn pin(
    number: &str,
    name: &str,
    net: Option<&str>,
    electrical_type: ElectricalPinType,
) -> CircuitPinV2 {
    CircuitPinV2 {
        number: number.into(),
        name: name.into(),
        net: net.map(str::to_owned),
        electrical_type,
    }
}

fn connection(reference: &str, pin: &str) -> CircuitConnectionV2 {
    CircuitConnectionV2 {
        reference: reference.into(),
        pin: pin.into(),
    }
}

fn base_spec() -> CircuitSpecV2 {
    CircuitSpecV2 {
        schema_version: 2,
        parts: vec![
            CircuitPartV2 {
                reference: "U1".into(),
                lib_id: "MCU:Controller".into(),
                value: "controller".into(),
                footprint: "Package_QFN:QFN-16".into(),
                mpn: Some("CTRL-1".into()),
                power: power(None, Some(3_300_000), true, false),
                pins: vec![
                    pin("1", "VDD", Some("PWR"), ElectricalPinType::PowerInput),
                    pin("2", "SIG", Some("SIG"), ElectricalPinType::Input),
                    pin("3", "NC", None, ElectricalPinType::NoConnect),
                    pin("4", "GND", Some("GND"), ElectricalPinType::Passive),
                ],
            },
            CircuitPartV2 {
                reference: "U2".into(),
                lib_id: "Regulator:Output".into(),
                value: "3V3 regulator".into(),
                footprint: "Package_SOT:SOT-23".into(),
                mpn: Some("REG-3V3".into()),
                power: power(Some(3_300_000), None, false, false),
                pins: vec![
                    pin("1", "OUT", Some("PWR"), ElectricalPinType::PowerOutput),
                    pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
                ],
            },
            CircuitPartV2 {
                reference: "U3".into(),
                lib_id: "Logic:Driver".into(),
                value: "signal driver".into(),
                footprint: "Package_SOT:SOT-23".into(),
                mpn: Some("DRV-1".into()),
                power: power(None, None, false, false),
                pins: vec![
                    pin("1", "OUT", Some("SIG"), ElectricalPinType::Output),
                    pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
                ],
            },
            CircuitPartV2 {
                reference: "C1".into(),
                lib_id: "Device:C".into(),
                value: "100nF".into(),
                footprint: "Capacitor_SMD:C_0603".into(),
                mpn: Some("CAP-100N".into()),
                power: power(None, None, false, true),
                pins: vec![
                    pin("1", "1", Some("PWR"), ElectricalPinType::Passive),
                    pin("2", "2", Some("GND"), ElectricalPinType::Passive),
                ],
            },
        ],
        nets: vec![
            CircuitNetV2 {
                name: "PWR".into(),
                voltage_uv: Some(3_300_000),
                connections: vec![
                    connection("U1", "1"),
                    connection("U2", "1"),
                    connection("C1", "1"),
                ],
            },
            CircuitNetV2 {
                name: "SIG".into(),
                voltage_uv: None,
                connections: vec![connection("U1", "2"), connection("U3", "1")],
            },
            CircuitNetV2 {
                name: "GND".into(),
                voltage_uv: None,
                connections: vec![
                    connection("U1", "4"),
                    connection("U2", "2"),
                    connection("U3", "2"),
                    connection("C1", "2"),
                ],
            },
        ],
    }
}

fn rules(check: &pcbex_kicad::CircuitSpecCheck) -> Vec<&str> {
    check
        .electrical_review
        .findings
        .iter()
        .map(|finding| finding.rule.as_str())
        .collect()
}

fn assert_schema_refs_resolve(schema: &Value) {
    let definitions = schema["$defs"].as_object().expect("schema $defs");
    fn walk(value: &Value, definitions: &serde_json::Map<String, Value>) {
        match value {
            Value::String(reference) => {
                if let Some(name) = reference.strip_prefix("#/$defs/") {
                    assert!(
                        definitions.contains_key(name),
                        "unresolved schema definition reference: {reference}"
                    );
                }
            }
            Value::Array(values) => {
                for value in values {
                    walk(value, definitions);
                }
            }
            Value::Object(values) => {
                for value in values.values() {
                    walk(value, definitions);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    walk(schema, definitions);
}

fn assert_missing_key_is_rejected(mut value: Value, remove: impl FnOnce(&mut Value)) {
    remove(&mut value);
    let source = serde_json::to_string(&value).unwrap();
    assert!(
        pcbex_kicad::parse_circuit_spec_v2(&source).is_err(),
        "missing nullable key unexpectedly accepted: {source}"
    );
}

#[test]
fn normalization_and_digests_are_deterministic() {
    let mut first = base_spec();
    let mut second = base_spec();
    second.parts.reverse();
    second.nets.reverse();
    for part in &mut second.parts {
        part.pins.reverse();
    }
    for net in &mut second.nets {
        net.connections.reverse();
    }
    let normalized = normalize_circuit_spec_v2(&first).unwrap();
    let repeated = normalize_circuit_spec_v2(&second).unwrap();
    assert_eq!(normalized, repeated);
    first = normalized.clone();
    let left = check_circuit_spec(&first).unwrap();
    let right = check_circuit_spec(&second).unwrap();
    assert_eq!(left, right);
    assert!(left.electrical_review.approved, "{:?}", rules(&left));
    assert_eq!(left.schema_version, 1);
    assert_eq!(left.circuit_spec_sha256.len(), 64);
    assert_eq!(left.electrical_review_sha256.len(), 64);
    assert_eq!(left.normalized_spec.parts[0].reference, "C1");
    assert_eq!(left.normalized_spec.nets[0].name, "GND");
    let document = pcbex_kicad::circuit_spec_v2_to_schematic(&first).unwrap();
    assert!(document.coverage.complete);
    assert_eq!(document.nets[0].id, 1);
    assert_eq!(document.nets[0].name, "GND");
    assert_eq!(document.symbols[0].pins[0].number, "1");
    let capacitor = document
        .symbols
        .iter()
        .find(|symbol| symbol.reference == "C1")
        .unwrap();
    assert_eq!(
        capacitor.properties.get("pcbex:mpn").map(String::as_str),
        Some("CAP-100N")
    );
}

#[test]
fn immutable_erc_reports_power_and_signal_errors() {
    let mut signal = base_spec();
    signal.parts.push(CircuitPartV2 {
        reference: "U4".into(),
        lib_id: "Logic:Driver".into(),
        value: "second signal driver".into(),
        footprint: "Package_SOT:SOT-23".into(),
        mpn: Some("DRV-2".into()),
        power: power(None, None, false, false),
        pins: vec![
            pin("1", "OUT", Some("SIG"), ElectricalPinType::Output),
            pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
        ],
    });
    signal
        .nets
        .iter_mut()
        .find(|net| net.name == "SIG")
        .unwrap()
        .connections
        .push(connection("U4", "1"));
    signal
        .nets
        .iter_mut()
        .find(|net| net.name == "GND")
        .unwrap()
        .connections
        .push(connection("U4", "2"));
    let check = check_circuit_spec(&signal).unwrap();
    assert!(rules(&check).contains(&"multiple_output_drivers"));

    let mut power_outputs = base_spec();
    power_outputs.parts.push(CircuitPartV2 {
        reference: "U4".into(),
        lib_id: "Regulator:Output".into(),
        value: "second power output".into(),
        footprint: "Package_SOT:SOT-23".into(),
        mpn: Some("REG-2".into()),
        power: power(None, None, false, false),
        pins: vec![
            pin("1", "OUT", Some("PWR"), ElectricalPinType::PowerOutput),
            pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
        ],
    });
    power_outputs
        .nets
        .iter_mut()
        .find(|net| net.name == "PWR")
        .unwrap()
        .connections
        .push(connection("U4", "1"));
    power_outputs
        .nets
        .iter_mut()
        .find(|net| net.name == "GND")
        .unwrap()
        .connections
        .push(connection("U4", "2"));
    let check = check_circuit_spec(&power_outputs).unwrap();
    assert!(rules(&check).contains(&"multiple_power_outputs"));

    let mut undriven = base_spec();
    undriven.parts.push(CircuitPartV2 {
        reference: "U4".into(),
        lib_id: "MCU:Input".into(),
        value: "power input".into(),
        footprint: "Package_SOT:SOT-23".into(),
        mpn: Some("IN-1".into()),
        power: power(None, None, false, false),
        pins: vec![
            pin("1", "AUX", Some("AUX"), ElectricalPinType::PowerInput),
            pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
        ],
    });
    undriven.parts.push(CircuitPartV2 {
        reference: "R1".into(),
        lib_id: "Device:R".into(),
        value: "1k".into(),
        footprint: "Resistor_SMD:R_0603".into(),
        mpn: Some("RES-1".into()),
        power: power(None, None, false, false),
        pins: vec![
            pin("1", "AUX", Some("AUX"), ElectricalPinType::Passive),
            pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
        ],
    });
    undriven.nets.push(CircuitNetV2 {
        name: "AUX".into(),
        voltage_uv: Some(1_800_000),
        connections: vec![connection("U4", "1"), connection("R1", "1")],
    });
    undriven
        .nets
        .iter_mut()
        .find(|net| net.name == "GND")
        .unwrap()
        .connections
        .extend([connection("U4", "2"), connection("R1", "2")]);
    let check = check_circuit_spec(&undriven).unwrap();
    assert!(rules(&check).contains(&"power_input_not_driven"));

    let mut exceeded = base_spec();
    exceeded
        .parts
        .iter_mut()
        .find(|part| part.reference == "U1")
        .unwrap()
        .power
        .max_voltage_uv = Some(1_800_000);
    let check = check_circuit_spec(&exceeded).unwrap();
    assert!(rules(&check).contains(&"power_input_voltage_exceeded"));

    let mut missing_decoupling = base_spec();
    missing_decoupling
        .parts
        .iter_mut()
        .find(|part| part.reference == "C1")
        .unwrap()
        .power
        .decoupling = false;
    let check = check_circuit_spec(&missing_decoupling).unwrap();
    assert!(rules(&check).contains(&"missing_decoupling_capacitor"));

    let mut conflict = base_spec();
    conflict.parts.push(CircuitPartV2 {
        reference: "U4".into(),
        lib_id: "Regulator:Output".into(),
        value: "5V output".into(),
        footprint: "Package_SOT:SOT-23".into(),
        mpn: Some("REG-5V".into()),
        power: power(Some(5_000_000), None, false, false),
        pins: vec![
            pin("1", "OUT", Some("PWR"), ElectricalPinType::PowerOutput),
            pin("2", "GND", Some("GND"), ElectricalPinType::Passive),
        ],
    });
    conflict
        .nets
        .iter_mut()
        .find(|net| net.name == "PWR")
        .unwrap()
        .connections
        .push(connection("U4", "1"));
    conflict
        .nets
        .iter_mut()
        .find(|net| net.name == "GND")
        .unwrap()
        .connections
        .push(connection("U4", "2"));
    let check = check_circuit_spec(&conflict).unwrap();
    assert!(rules(&check).contains(&"power_rail_voltage_conflict"));
}

#[test]
fn malformed_specs_and_closed_schemas_fail_closed() {
    let mut duplicate = base_spec();
    duplicate.parts[1].reference = "U1".into();
    assert!(normalize_circuit_spec_v2(&duplicate).is_err());

    let mut inconsistent = base_spec();
    inconsistent.parts[0].pins[1].net = Some("GND".into());
    assert!(normalize_circuit_spec_v2(&inconsistent).is_err());

    let mut cross_net = base_spec();
    cross_net.nets[1].connections.push(connection("U1", "1"));
    assert!(normalize_circuit_spec_v2(&cross_net).is_err());

    let mut no_connect = base_spec();
    no_connect.nets[0].connections.push(connection("U1", "3"));
    assert!(normalize_circuit_spec_v2(&no_connect).is_err());

    let mut short_net = base_spec();
    short_net.nets[0].connections.truncate(1);
    assert!(normalize_circuit_spec_v2(&short_net).is_err());

    let mut no_nets = base_spec();
    no_nets.nets.clear();
    assert!(normalize_circuit_spec_v2(&no_nets).is_err());

    for invalid_lib_id in ["Controller", ":Controller", "MCU:", "MCU:Core:Controller"] {
        let mut invalid = base_spec();
        invalid.parts[0].lib_id = invalid_lib_id.into();
        assert!(normalize_circuit_spec_v2(&invalid).is_err());
    }

    let mut unspecified = base_spec();
    unspecified.parts[0].pins[0].electrical_type = ElectricalPinType::Unspecified;
    assert!(normalize_circuit_spec_v2(&unspecified).is_err());

    let mut power_metadata = base_spec();
    power_metadata.parts[2].power.max_voltage_uv = Some(1_800_000);
    assert!(normalize_circuit_spec_v2(&power_metadata).is_err());

    let mut optional_mpn = base_spec();
    optional_mpn.parts[0].mpn = None;
    assert!(normalize_circuit_spec_v2(&optional_mpn).is_ok());

    let serialized = serde_json::to_value(base_spec()).unwrap();
    assert_missing_key_is_rejected(serialized.clone(), |value| {
        value["parts"][0].as_object_mut().unwrap().remove("mpn");
    });
    assert_missing_key_is_rejected(serialized.clone(), |value| {
        value["parts"][0]["power"]
            .as_object_mut()
            .unwrap()
            .remove("rail_voltage_uv");
    });
    assert_missing_key_is_rejected(serialized.clone(), |value| {
        value["parts"][0]["power"]
            .as_object_mut()
            .unwrap()
            .remove("max_voltage_uv");
    });
    assert_missing_key_is_rejected(serialized.clone(), |value| {
        value["parts"][0]["pins"][0]
            .as_object_mut()
            .unwrap()
            .remove("net");
    });
    assert_missing_key_is_rejected(serialized, |value| {
        value["nets"][0]
            .as_object_mut()
            .unwrap()
            .remove("voltage_uv");
    });

    let mut explicit_null = serde_json::to_value(base_spec()).unwrap();
    explicit_null["parts"][0]["mpn"] = Value::Null;
    explicit_null["parts"][0]["power"]["rail_voltage_uv"] = Value::Null;
    explicit_null["parts"][0]["pins"][0]["net"] = json!("PWR");
    explicit_null["nets"][1]["voltage_uv"] = Value::Null;
    assert!(
        pcbex_kicad::parse_circuit_spec_v2(&serde_json::to_string(&explicit_null).unwrap()).is_ok()
    );

    let unknown = serde_json::to_string(&json!({
        "schema_version": 2,
        "parts": [],
        "nets": [],
        "unknown": true
    }))
    .unwrap();
    assert!(pcbex_kicad::parse_circuit_spec_v2(&unknown).is_err());
    let duplicate_json = r#"{"schema_version":2,"schema_version":2,"parts":[],"nets":[]}"#;
    let duplicate_error = pcbex_kicad::parse_circuit_spec_v2(duplicate_json).unwrap_err();
    assert!(duplicate_error.contains("duplicate JSON object key"));
    assert_schema_refs_resolve(&circuit_spec_v2_json_schema());
    assert_schema_refs_resolve(&circuit_spec_check_json_schema());
    let schema = circuit_spec_v2_json_schema();
    assert_eq!(
        schema["$defs"]["part"]["properties"]["reference"]["pattern"],
        "^[A-Za-z][A-Za-z0-9_]*$"
    );
    assert_eq!(schema["properties"]["nets"]["minItems"], 1);
    assert_eq!(
        schema["$defs"]["part"]["properties"]["lib_id"]["pattern"],
        "^[^:\\u0000-\\u001F\\u007F-\\u009F]*[^\\s:\\u0000-\\u001F\\u007F-\\u009F][^:\\u0000-\\u001F\\u007F-\\u009F]*:[^:\\u0000-\\u001F\\u007F-\\u009F]*[^\\s:\\u0000-\\u001F\\u007F-\\u009F][^:\\u0000-\\u001F\\u007F-\\u009F]*$"
    );
    assert_eq!(
        schema["$defs"]["pin"]["properties"]["number"]["pattern"],
        "^[A-Za-z0-9_+./-]+$"
    );
    assert_eq!(
        schema["$defs"]["net"]["properties"]["name"]["pattern"],
        "^[A-Za-z0-9_+./-]+$"
    );
    assert_eq!(
        schema["$defs"]["part"]["properties"]["mpn"]["anyOf"][0]["minLength"],
        1
    );
    assert_eq!(
        schema["$defs"]["pin"]["properties"]["net"]["anyOf"][0]["minLength"],
        1
    );
    assert!(
        !schema["$defs"]["pin"]["properties"]["electrical_type"]["enum"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value == "unspecified")
    );
    assert!(
        !circuit_spec_v2_json_schema()["additionalProperties"]
            .as_bool()
            .unwrap()
    );
    assert!(
        !circuit_spec_check_json_schema()["additionalProperties"]
            .as_bool()
            .unwrap()
    );
}

#[test]
fn cli_checks_circuit_spec_and_publishes_schemas() {
    let directory = temp_dir();
    let input = directory.join("spec.json");
    let output = directory.join("check.json");
    fs::write(&input, serde_json::to_vec_pretty(&base_spec()).unwrap()).unwrap();

    let input_before = fs::read(&input).unwrap();
    let aliased = Command::new(binary())
        .args(["check-circuit-spec", path(&input), "--output", path(&input)])
        .output()
        .unwrap();
    assert!(!aliased.status.success());
    assert!(String::from_utf8_lossy(&aliased.stderr).contains("must not alias input"));
    assert_eq!(fs::read(&input).unwrap(), input_before);

    let occupied = directory.join("occupied.json");
    fs::write(&occupied, b"sentinel").unwrap();
    let collision = Command::new(binary())
        .args([
            "check-circuit-spec",
            path(&input),
            "--output",
            path(&occupied),
        ])
        .output()
        .unwrap();
    assert!(!collision.status.success());
    assert!(String::from_utf8_lossy(&collision.stderr).contains("refusing to overwrite"));
    assert_eq!(fs::read(&occupied).unwrap(), b"sentinel");

    let checked = Command::new(binary())
        .args([
            "check-circuit-spec",
            path(&input),
            "--output",
            path(&output),
            "--require-approved",
        ])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["electrical_review"]["approved"], true);

    let v2_schema = directory.join("v2.schema.json");
    let check_schema = directory.join("check.schema.json");
    for (command, destination) in [
        ("circuit-spec-v2-schema", &v2_schema),
        ("circuit-spec-check-schema", &check_schema),
    ] {
        let result = Command::new(binary())
            .args([command, "--output", path(destination)])
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let schema: Value = serde_json::from_slice(&fs::read(destination).unwrap()).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }
    fs::remove_dir_all(directory).unwrap();
}

#[cfg(unix)]
#[test]
fn cli_refuses_circuit_spec_outputs_through_symlinks() {
    use std::os::unix::fs::symlink;

    let directory = temp_dir();
    let input = directory.join("spec.json");
    fs::write(&input, serde_json::to_vec_pretty(&base_spec()).unwrap()).unwrap();
    let target = directory.join("target.json");
    fs::write(&target, b"sentinel").unwrap();
    let linked_output = directory.join("linked-output.json");
    symlink(&target, &linked_output).unwrap();

    let direct = Command::new(binary())
        .args([
            "check-circuit-spec",
            path(&input),
            "--output",
            path(&linked_output),
        ])
        .output()
        .unwrap();
    assert!(!direct.status.success());
    assert!(String::from_utf8_lossy(&direct.stderr).contains("symlink"));
    assert_eq!(fs::read(&target).unwrap(), b"sentinel");

    let real_parent = directory.join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = directory.join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    let parent = Command::new(binary())
        .args([
            "check-circuit-spec",
            path(&input),
            "--output",
            path(&linked_parent.join("check.json")),
        ])
        .output()
        .unwrap();
    assert!(!parent.status.success());
    assert!(String::from_utf8_lossy(&parent.stderr).contains("symlink"));
    assert!(!real_parent.join("check.json").exists());

    fs::remove_dir_all(directory).unwrap();
}
