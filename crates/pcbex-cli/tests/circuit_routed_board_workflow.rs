use pcbex_kicad::{
    circuit_spec_v2_sha256, circuit_spec_v3_sha256, circuit_spec_v3_to_physical_v2,
    parse_circuit_spec_v3,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pcbex"))
}
fn example(name: &str) -> PathBuf {
    root().join("examples").join(name)
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn run(args: &[String]) -> Output {
    Command::new(binary()).args(args).output().unwrap()
}

fn canonical_tempdir() -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let canonical = fs::canonicalize(directory.path()).unwrap();
    (directory, canonical)
}

fn generate(spec: &Path, out: &Path, extra: &[&str]) -> Output {
    generate_with_construction(
        spec,
        out,
        &example("circuit-board-construction-profile-v1.json"),
        extra,
    )
}

fn generate_with_construction(
    spec: &Path,
    out: &Path,
    construction: &Path,
    extra: &[&str],
) -> Output {
    let mut args = vec![
        "generate-circuit-kicad-routed-board".into(),
        path(spec).into(),
        "--footprint-closure".into(),
        path(&example("circuit-board-footprint-closure-v1.json")).into(),
        "--construction-profile".into(),
        path(construction).into(),
        "--physical-profile".into(),
        path(&example("circuit-board-physical-profile-v1.json")).into(),
        "--output-dir".into(),
        path(out).into(),
    ];
    args.extend(extra.iter().map(|v| (*v).to_string()));
    run(&args)
}

fn assert_success(result: Output) {
    assert!(
        result.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

fn assert_closed_schema(value: &Value) {
    if value.get("type") == Some(&Value::String("object".into())) {
        assert_eq!(value["additionalProperties"], false);
    }
    if value.get("type") == Some(&Value::String("array".into())) {
        assert!(value.get("maxItems").is_some());
    }
    match value {
        Value::Array(v) => v.iter().for_each(assert_closed_schema),
        Value::Object(v) => v.values().for_each(assert_closed_schema),
        _ => {}
    }
}

fn output_names(dir: &Path) -> Vec<String> {
    let mut names = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    names
}

const OUTPUTS: [&str; 14] = [
    "board-binding.json",
    "board.kicad_pcb",
    "board.placed-binding.json",
    "board.placed.kicad_pcb",
    "board.placed-manifest.json",
    "circuit-handoff.json",
    "circuit.kicad_sch",
    "circuit-spec.json",
    "construction-profile.json",
    "footprint-closure.json",
    "manifest.json",
    "physical-profile.json",
    "routing-convergence.json",
    "routing-verification.json",
];

#[test]
fn v2_workflow_is_deterministic_and_replays_all_retained_evidence() {
    let (_guard, temp) = canonical_tempdir();
    let spec = example("circuit-board-spec-v2.json");
    let first = temp.join("first");
    let second = temp.join("second");
    assert_success(generate(
        &spec,
        &first,
        &[
            "--convergence-rounds",
            "2",
            "--convergence-candidates",
            "3",
            "--convergence-workers",
            "2",
            "--convergence-router-workers",
            "1",
        ],
    ));
    assert_success(generate(
        &spec,
        &second,
        &[
            "--convergence-rounds",
            "2",
            "--convergence-candidates",
            "3",
            "--convergence-workers",
            "2",
            "--convergence-router-workers",
            "1",
        ],
    ));
    let mut expected_names = OUTPUTS.to_vec();
    expected_names.sort_unstable();
    assert_eq!(output_names(&first), expected_names);
    for name in OUTPUTS {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(second.join(name)).unwrap(),
            "{name}"
        );
    }
    for (name, source) in [
        ("circuit-spec.json", &spec),
        (
            "footprint-closure.json",
            &example("circuit-board-footprint-closure-v1.json"),
        ),
        (
            "construction-profile.json",
            &example("circuit-board-construction-profile-v1.json"),
        ),
        (
            "physical-profile.json",
            &example("circuit-board-physical-profile-v1.json"),
        ),
    ] {
        assert_eq!(
            fs::read(first.join(name)).unwrap(),
            fs::read(source).unwrap(),
            "raw snapshot {name}"
        );
    }
    let manifest: Value =
        serde_json::from_slice(&fs::read(first.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["schema_version"], 1);
    assert_eq!(manifest["status"], "verified_complete");
    assert_eq!(manifest["scope"], "circuit_kicad_routed_board_workflow");
    for field in [
        "human_approval_verified",
        "native_kicad_drc_verified",
        "manufacturability_verified",
        "release_authorized",
        "source_authenticity_verified",
    ] {
        assert_eq!(manifest[field], false, "{field}");
    }
    assert_eq!(manifest["internal_rule_check_verified"], true);
    for (role, file) in [
        ("circuit_spec", "circuit-spec.json"),
        ("footprint_closure", "footprint-closure.json"),
        ("construction_profile", "construction-profile.json"),
        ("physical_profile", "physical-profile.json"),
    ] {
        let bytes = fs::read(first.join(file)).unwrap();
        assert_eq!(manifest[role]["bytes"], bytes.len() as u64);
        assert_eq!(
            manifest[role]["sha256"],
            hex::encode(Sha256::digest(&bytes))
        );
    }
    for artifact in manifest["outputs"].as_array().unwrap() {
        let bytes = fs::read(first.join(artifact["name"].as_str().unwrap())).unwrap();
        assert_eq!(artifact["identity"]["bytes"], bytes.len() as u64);
        assert_eq!(
            artifact["identity"]["sha256"],
            hex::encode(Sha256::digest(&bytes))
        );
    }
    let rules = &manifest["effective_rules"];
    for (key, value) in [
        ("grid_nm", 100000),
        ("track_width_nm", 250000),
        ("clearance_nm", 200000),
        ("via_diameter_nm", 660000),
        ("via_drill_nm", 300000),
        ("bend_cost", 5),
        ("via_cost", 50),
    ] {
        assert_eq!(rules[key], value, "effective rule {key}");
    }

    let fresh_binding = temp.join("fresh-binding.json");
    assert_success(run(&[
        "verify-circuit-kicad-board-binding".into(),
        path(&first.join("circuit-spec.json")).into(),
        path(&first.join("circuit.kicad_sch")).into(),
        path(&first.join("board.placed.kicad_pcb")).into(),
        "--output".into(),
        path(&fresh_binding).into(),
        "--require-approved".into(),
    ]));
    assert_eq!(
        fs::read(fresh_binding).unwrap(),
        fs::read(first.join("board.placed-binding.json")).unwrap()
    );

    let fresh = temp.join("fresh-routing-verification.json");
    assert_success(run(&[
        "verify-kicad-routing-convergence".into(),
        path(&first.join("board.placed.kicad_pcb")).into(),
        "--routed".into(),
        path(&first.join("board.kicad_pcb")).into(),
        "--report".into(),
        path(&first.join("routing-convergence.json")).into(),
        "--physical-profile".into(),
        path(&first.join("physical-profile.json")).into(),
        "--grid-mm".into(),
        "0.1".into(),
        "--width-mm".into(),
        "0.25".into(),
        "--clearance-mm".into(),
        "0.2".into(),
        "--via-diameter-mm".into(),
        "0.66".into(),
        "--via-drill-mm".into(),
        "0.3".into(),
        "--bend-cost".into(),
        "5".into(),
        "--via-cost".into(),
        "50".into(),
        "--output".into(),
        path(&fresh).into(),
        "--require-complete".into(),
    ]));
    assert_eq!(
        fs::read(fresh).unwrap(),
        fs::read(first.join("routing-verification.json")).unwrap()
    );
    let routed_binding = temp.join("routed-binding.json");
    assert_success(run(&[
        "verify-circuit-kicad-board-binding".into(),
        path(&first.join("circuit-spec.json")).into(),
        path(&first.join("circuit.kicad_sch")).into(),
        path(&first.join("board.kicad_pcb")).into(),
        "--output".into(),
        path(&routed_binding).into(),
        "--require-approved".into(),
    ]));
    assert_eq!(
        fs::read(routed_binding).unwrap(),
        fs::read(first.join("board-binding.json")).unwrap()
    );
    let fresh_handoff = temp.join("fresh-handoff.json");
    assert_success(run(&[
        "verify-circuit-kicad-handoff".into(),
        path(&first.join("circuit-spec.json")).into(),
        path(&first.join("circuit.kicad_sch")).into(),
        "--output".into(),
        path(&fresh_handoff).into(),
        "--require-approved".into(),
    ]));
    assert_eq!(
        fs::read(fresh_handoff).unwrap(),
        fs::read(first.join("circuit-handoff.json")).unwrap()
    );
}

#[test]
fn v3_manifest_preserves_canonical_original_digest() {
    let (_guard, temp) = canonical_tempdir();
    let spec = example("circuit-board-spec-v3.json");
    let out = temp.join("v3");
    assert_success(generate(&spec, &out, &[]));
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    let handoff: Value =
        serde_json::from_slice(&fs::read(out.join("circuit-handoff.json")).unwrap()).unwrap();
    assert_eq!(
        manifest["circuit_spec_sha256"],
        handoff["circuit_spec_sha256"]
    );
    let parsed = parse_circuit_spec_v3(&fs::read_to_string(&spec).unwrap()).unwrap();
    let original = circuit_spec_v3_sha256(&parsed).unwrap();
    let projected =
        circuit_spec_v2_sha256(&circuit_spec_v3_to_physical_v2(&parsed).unwrap()).unwrap();
    assert_eq!(manifest["circuit_spec_sha256"], original);
    assert_ne!(original, projected);
}

#[test]
fn workflow_retains_nondefault_construction_routing_rules() {
    let (_guard, temp) = canonical_tempdir();
    let spec = example("circuit-board-spec-v2.json");
    let mut profile: Value = serde_json::from_slice(
        &fs::read(example("circuit-board-construction-profile-v1.json")).unwrap(),
    )
    .unwrap();
    for (key, value) in [
        ("grid_nm", 100000),
        ("track_width_nm", 270000),
        ("clearance_nm", 210000),
        ("via_diameter_nm", 720000),
        ("via_drill_nm", 320000),
        ("bend_cost", 9),
        ("via_cost", 31),
    ] {
        profile["routing_defaults"][key] = value.into();
    }
    let construction = temp.join("construction.json");
    fs::write(&construction, serde_json::to_vec_pretty(&profile).unwrap()).unwrap();
    let out = temp.join("custom");
    assert_success(generate_with_construction(&spec, &out, &construction, &[]));
    let manifest: Value =
        serde_json::from_slice(&fs::read(out.join("manifest.json")).unwrap()).unwrap();
    for (key, value) in [
        ("grid_nm", 100000),
        ("track_width_nm", 270000),
        ("clearance_nm", 210000),
        ("via_diameter_nm", 720000),
        ("via_drill_nm", 320000),
        ("bend_cost", 9),
        ("via_cost", 31),
    ] {
        assert_eq!(manifest["effective_rules"][key], value);
    }
}

#[test]
fn rejects_tampering_aliases_overwrites_and_unbound_options_without_output() {
    let (_guard, temp) = canonical_tempdir();
    let spec = example("circuit-board-spec-v2.json");
    let closure = temp.join("tampered.json");
    let mut value: Value = serde_json::from_slice(
        &fs::read(example("circuit-board-footprint-closure-v1.json")).unwrap(),
    )
    .unwrap();
    value["footprints"][0]["source_sha256"] = Value::String("0".repeat(64));
    fs::write(&closure, serde_json::to_vec(&value).unwrap()).unwrap();
    let out = temp.join("tampered-out");
    let result = {
        let args = vec![
            "generate-circuit-kicad-routed-board".into(),
            path(&spec).into(),
            "--footprint-closure".into(),
            path(&closure).into(),
            "--construction-profile".into(),
            path(&example("circuit-board-construction-profile-v1.json")).into(),
            "--physical-profile".into(),
            path(&example("circuit-board-physical-profile-v1.json")).into(),
            "--output-dir".into(),
            path(&out).into(),
        ];
        run(&args)
    };
    assert!(!result.status.success());
    assert!(!out.exists());
    let existing = temp.join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("keep"), b"keep").unwrap();
    assert!(!generate(&spec, &existing, &[]).status.success());
    assert_eq!(fs::read(existing.join("keep")).unwrap(), b"keep");
    let alias = temp.join("alias");
    fs::write(&alias, b"alias").unwrap();
    assert!(!generate(&spec, &alias, &[]).status.success());
    assert_eq!(fs::read(&alias).unwrap(), b"alias");
    #[cfg(unix)]
    {
        let target = temp.join("symlink-target");
        fs::create_dir(&target).unwrap();
        let link = temp.join("symlink-output");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!generate(&spec, &link, &[]).status.success());
        assert!(target.read_dir().unwrap().next().is_none());
    }
    let invalid = temp.join("invalid");
    assert!(
        !generate(&spec, &invalid, &["--allow-unrouted"])
            .status
            .success()
    );
    assert!(!invalid.exists());
    assert!(
        !generate(&spec, &invalid, &["--grid-mm", "0.1"])
            .status
            .success()
    );
    assert!(!invalid.exists());
}

#[test]
fn low_budget_retains_no_admissible_report_but_publishes_no_workflow_directory() {
    let (_guard, temp) = canonical_tempdir();
    let spec = example("circuit-board-spec-v2.json");
    let out = temp.join("partial");
    let result = generate(
        &spec,
        &out,
        &[
            "--convergence-rounds",
            "1",
            "--convergence-candidates",
            "1",
            "--convergence-workers",
            "1",
            "--convergence-router-workers",
            "1",
            "--convergence-work-budget",
            "1",
        ],
    );
    assert!(!result.status.success());
    assert!(!out.exists());
}

#[test]
fn workflow_manifest_schema_is_closed() {
    let (_guard, temp) = canonical_tempdir();
    let schema = temp.join("schema.json");
    assert_success(run(&[
        "circuit-kicad-routed-board-manifest-schema".into(),
        "--output".into(),
        path(&schema).into(),
    ]));
    let value: Value = serde_json::from_slice(&fs::read(schema).unwrap()).unwrap();
    assert_closed_schema(&value);
    assert_eq!(value["additionalProperties"], false);
    for (definition, count) in [("rules", 7), ("options", 5)] {
        let object = &value["$defs"][definition];
        assert_eq!(object["required"].as_array().unwrap().len(), count);
        assert_eq!(object["properties"].as_object().unwrap().len(), count);
        for field in object["required"].as_array().unwrap() {
            assert!(object["properties"].get(field.as_str().unwrap()).is_some());
        }
    }
    assert_eq!(
        value["$defs"]["options"]["properties"]["candidate_workers"]["maximum"],
        8
    );
    assert_eq!(
        value["properties"]["outputs"]["prefixItems"]
            .as_array()
            .unwrap()
            .len(),
        9
    );
    assert_eq!(value["properties"]["outputs"]["items"], false);
}
