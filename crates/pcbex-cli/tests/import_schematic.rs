use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn imports_a_deterministic_complete_schematic_ir() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("examples/simple.kicad_sch");
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock must follow Unix epoch")
        .as_nanos();
    let output = std::env::temp_dir().join(format!(
        "pcbex-schematic-ir-{}-{unique}.json",
        std::process::id()
    ));
    let repeated_output = output.with_extension("repeated.json");
    let schema_output = output.with_extension("schema.json");
    let result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .args([
            "import-schematic",
            input.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--require-complete",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "pcbex failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let repeated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .args([
            "import-schematic",
            input.to_str().unwrap(),
            "--output",
            repeated_output.to_str().unwrap(),
            "--require-complete",
        ])
        .output()
        .unwrap();
    assert!(repeated.status.success());
    assert_eq!(
        fs::read(&output).unwrap(),
        fs::read(&repeated_output).unwrap()
    );
    let document: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(document["schema_version"], 1);
    assert_eq!(document["coverage"]["complete"], true);
    assert_eq!(document["symbols"].as_array().unwrap().len(), 2);
    assert!(
        document["nets"]
            .as_array()
            .unwrap()
            .iter()
            .any(|net| net["name"] == "SIGNAL" && net["pins"].as_array().unwrap().len() == 2)
    );
    let schema_result = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .args([
            "schematic-schema",
            "--output",
            schema_output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(schema_result.status.success());
    let schema: Value = serde_json::from_slice(&fs::read(&schema_output).unwrap()).unwrap();
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);

    let incomplete_input = output.with_extension("incomplete.kicad_sch");
    let incomplete_output = output.with_extension("incomplete.json");
    let source = fs::read_to_string(&input).unwrap().replace(
        "(sheet_instances",
        "(sheet (at 1 1) (size 2 2) (uuid 00000000-0000-0000-0000-000000000099))\n\
         (sheet_instances",
    );
    fs::write(&incomplete_input, source).unwrap();
    let gated = Command::new(env!("CARGO_BIN_EXE_pcbex"))
        .args([
            "import-schematic",
            incomplete_input.to_str().unwrap(),
            "--output",
            incomplete_output.to_str().unwrap(),
            "--require-complete",
        ])
        .output()
        .unwrap();
    assert!(!gated.status.success());
    let incomplete: Value = serde_json::from_slice(&fs::read(&incomplete_output).unwrap()).unwrap();
    assert_eq!(incomplete["coverage"]["complete"], false);

    fs::remove_file(output).unwrap();
    fs::remove_file(repeated_output).unwrap();
    fs::remove_file(schema_output).unwrap();
    fs::remove_file(incomplete_input).unwrap();
    fs::remove_file(incomplete_output).unwrap();
}
