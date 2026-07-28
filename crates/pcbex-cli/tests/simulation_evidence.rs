use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}

fn run(arguments: &[&str]) -> Output {
    Command::new(binary()).args(arguments).output().unwrap()
}

fn path(value: &Path) -> &str {
    value.to_str().unwrap()
}

fn temp_dir() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("pcbex-simulation-{suffix}"));
    fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn binds_raw_artifacts_and_gates_simulation_assertions() {
    let directory = temp_dir();
    let schematic =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/simple.kicad_sch");
    let policy = directory.join("policy.json");
    assert!(
        run(&["electrical-policy", "--output", path(&policy)])
            .status
            .success()
    );
    let mut policy_value: Value = serde_json::from_slice(&fs::read(&policy).unwrap()).unwrap();
    for setting in policy_value["rules"].as_object_mut().unwrap().values_mut() {
        if setting["severity"] == "error" {
            setting["enabled"] = Value::Bool(false);
        }
    }
    fs::write(&policy, serde_json::to_vec_pretty(&policy_value).unwrap()).unwrap();
    let review = directory.join("review.json");
    assert!(
        run(&[
            "check-schematic",
            path(&schematic),
            "--policy",
            path(&policy),
            "--output",
            path(&review),
            "--require-approved",
        ])
        .status
        .success()
    );
    let review_value: Value = serde_json::from_slice(&fs::read(&review).unwrap()).unwrap();

    let declaration = directory.join("declaration.json");
    let declaration_value = json!({
        "schema_version": 1,
        "id": "power-rail-dc",
        "analysis": "dc_operating_point",
        "simulator": {"name": "ngspice", "version": "42"},
        "schematic_sha256": review_value["schematic_sha256"],
        "assertions": [{
            "id": "vout",
            "description": "regulated output",
            "measured": 3.3,
            "unit": "V",
            "minimum": 3.2,
            "maximum": 3.4
        }]
    });
    fs::write(
        &declaration,
        serde_json::to_vec_pretty(&declaration_value).unwrap(),
    )
    .unwrap();
    let raw = directory.join("raw.csv");
    fs::write(&raw, "time,vout\n0,3.3\n").unwrap();

    let first = directory.join("first.json");
    let second = directory.join("second.json");
    for output in [&first, &second] {
        assert!(
            run(&[
                "record-simulation-evidence",
                path(&declaration),
                "--electrical-review",
                path(&review),
                "--artifact",
                path(&raw),
                "--output",
                path(output),
                "--require-passed",
            ])
            .status
            .success()
        );
    }
    assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());
    let evidence: Value = serde_json::from_slice(&fs::read(&first).unwrap()).unwrap();
    assert_eq!(evidence["passed"], true);
    assert_eq!(evidence["artifacts"][0]["name"], "raw.csv");
    assert_eq!(evidence["artifacts"][0]["bytes"], 16);

    let mut failing = declaration_value;
    failing["assertions"][0]["measured"] = json!(3.5);
    fs::write(&declaration, serde_json::to_vec_pretty(&failing).unwrap()).unwrap();
    let failed = directory.join("failed.json");
    let output = run(&[
        "record-simulation-evidence",
        path(&declaration),
        "--electrical-review",
        path(&review),
        "--artifact",
        path(&raw),
        "--output",
        path(&failed),
        "--require-passed",
    ]);
    assert!(!output.status.success());
    assert!(failed.is_file());

    for (command, filename) in [
        ("simulation-declaration-schema", "declaration.schema.json"),
        ("simulation-evidence-schema", "evidence.schema.json"),
    ] {
        let output = directory.join(filename);
        assert!(run(&[command, "--output", path(&output)]).status.success());
        let schema: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(schema["additionalProperties"], false);
    }

    fs::remove_dir_all(directory).unwrap();
}
